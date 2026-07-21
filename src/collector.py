import requests
import datetime
import pytz
import os
import re
import json
import time
import hashlib
from typing import List, Dict, Set, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from logger import logger
from rate_limiter import rate_limit_manager
import enrichment_sources

class CollectorError(Exception):
    """데이터 수집 관련 에러"""
    pass

# ─────────────────────────────────────────────
# 워터마크(진행 지점 북마크) — 누락 0 수집의 핵심
# GitHub Actions 무료 cron은 불규칙(수시간~수일 지연)이라 "최근 N시간" 고정 창은
# 실행 간격이 창보다 크면 그 사이 CVE를 영구 누락한다. 대신 "마지막으로 처리한
# 시각"을 파일에 기록하고, 다음 실행이 그 시각 이후 전부를 조회해 빈틈을 없앤다.
# 파일은 워크플로가 매 실행 docs/data/를 커밋하므로 git으로 영속된다(DB 불필요).
# ─────────────────────────────────────────────
_STATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs", "data", "pipeline_state.json"
)
_BOOTSTRAP_HOURS = 24  # 상태 파일이 없을 때(최초 실행) 소급 조회 기간

def read_watermark() -> datetime.datetime:
    """마지막 처리 시각(UTC) 반환. 없으면 now - _BOOTSTRAP_HOURS."""
    try:
        with open(_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        wm = data.get("last_processed_until")
        if wm:
            return datetime.datetime.fromisoformat(wm.replace("Z", "+00:00"))
    except (OSError, ValueError, json.JSONDecodeError) as e:
        logger.info(f"워터마크 없음/파싱 실패({e}) → 최근 {_BOOTSTRAP_HOURS}h 부트스트랩")
    return datetime.datetime.now(pytz.UTC) - datetime.timedelta(hours=_BOOTSTRAP_HOURS)

def write_watermark(dt_utc: datetime.datetime) -> None:
    """처리 완료 지점(UTC)을 상태 파일에 기록."""
    try:
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
        payload = {"last_processed_until": dt_utc.astimezone(pytz.UTC).isoformat()}
        with open(_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        logger.info(f"워터마크 저장: {payload['last_processed_until']}")
    except OSError as e:
        logger.warning(f"워터마크 저장 실패: {e}")

class Collector:
    def __init__(self):
        self.kev_set: Set[str] = set()
        self.kev_date_added: Dict[str, str] = {}  # CVE → KEV 등재일 (gap-filler용)
        self.vulncheck_kev_set: Set[str] = set()
        self.epss_cache: Dict[str, float] = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(requests.exceptions.RequestException)
    )
    def fetch_kev(self) -> bool:
        """CISA KEV 목록 다운로드"""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            rate_limit_manager.check_and_wait("kev")
            logger.info("Fetching CISA KEV list...")
            
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            rate_limit_manager.record_call("kev")
            
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            self.kev_set = {vuln['cveID'] for vuln in vulns}
            # 등재일 매핑 — 최근 등재분 중 DB 미보유 CVE를 잡는 gap-filler에 사용
            self.kev_date_added = {vuln['cveID']: vuln.get('dateAdded', '') for vuln in vulns}

            logger.info(f"Loaded {len(self.kev_set)} KEV entries")
            return True
            
        except requests.exceptions.Timeout:
            logger.error("KEV API timeout after 15s")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"KEV fetch failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in fetch_kev: {e}")
            return False
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_epss(self, cve_ids: List[str]) -> Dict[str, float]:
        """EPSS 점수 배치 수집"""
        if not cve_ids:
            return {}
        
        chunk_size = 50
        total_chunks = (len(cve_ids) + chunk_size - 1) // chunk_size
        
        logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs ({total_chunks} batches)")
        
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            chunk_num = (i // chunk_size) + 1
            
            try:
                rate_limit_manager.check_and_wait("epss")
                
                url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                rate_limit_manager.record_call("epss")
                
                for item in response.json().get('data', []):
                    cve_id = item.get('cve')
                    epss = float(item.get('epss', 0.0))
                    self.epss_cache[cve_id] = epss
                
                logger.debug(f"EPSS batch {chunk_num}/{total_chunks} complete")
                
            except Exception as e:
                logger.warning(f"EPSS batch {chunk_num} failed: {e}")
                continue
        
        return self.epss_cache
    
    # ====================================================================
    # [3] 콘텐츠 해시 기반 스마트 필터링
    # ====================================================================

    def _compute_content_hash(self, json_data: dict) -> str:
        """CVE JSON에서 의미있는 필드만 추출하여 SHA-256 해시 생성.

        날짜/시간, assignerOrgId, serial 등 메타데이터 필드는 제외하여
        벌크 메타데이터 패치(날짜 형식 변경 등)에 영향받지 않음.
        """
        cna = json_data.get('containers', {}).get('cna', {})
        meaningful = {
            "descriptions": cna.get('descriptions', []),
            "affected": cna.get('affected', []),
            "metrics": cna.get('metrics', []),
            "problemTypes": cna.get('problemTypes', []),
            "references": cna.get('references', []),
            "title": cna.get('title', ''),
            "state": json_data.get('cveMetadata', {}).get('state', ''),
        }
        canonical = json.dumps(meaningful, sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _extract_cve_id(self, filename: str) -> Optional[str]:
        """파일명에서 CVE ID 추출"""
        if filename.endswith(".json") and "CVE-" in filename:
            match = re.search(r'(CVE-\d{4}-\d{4,7})', filename)
            if match:
                return match.group(1)
        return None

    def _fetch_raw_cve_json(self, cve_id: str) -> Optional[dict]:
        """raw.githubusercontent.com에서 CVE JSON만 다운로드 (API 한도 미소모).

        enrich_cve()와 달리 NVD/EPSS/PoC 등 외부 API 호출 없음.
        해시 비교용 경량 사전 검사에 사용.
        """
        try:
            parts = cve_id.split('-')
            year, id_num = parts[1], parts[2]
            group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"

            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            response = requests.get(raw_url, timeout=15)
            response.raise_for_status()

            return response.json()
        except Exception as e:
            logger.debug(f"{cve_id} raw JSON 조회 실패: {e}")
            return None

    @staticmethod
    def _commit_ts(commit: dict) -> str:
        c = commit.get("commit", {})
        return (c.get("committer", {}) or {}).get("date") or (c.get("author", {}) or {}).get("date") or ""

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_cves_since(self, since_dt: datetime.datetime, db=None, max_commit_pages: int = 300,
                         until_dt: Optional[datetime.datetime] = None,
                         deadline_ts: Optional[float] = None) -> List[dict]:
        """워터마크(since_dt) 이후(선택적으로 until_dt까지) 커밋에서 변경된 CVE를 빠짐없이 수집.

        고정 시간창(누락 위험) 대신 '마지막 처리 지점' 이후 전부를 조회한다.
        스케줄이 아무리 불규칙해도(수시간·수일 지연) 빈틈이 생기지 않는다.
        until_dt는 초장기 공백 캐치업 시 한 실행의 조회량을 상한하기 위한 것 —
        창 밖(이후) 커밋은 다음 실행이 전진된 워터마크에서 이어서 수집한다.
        deadline_ts(time.time() 기준)는 소프트 데드라인 — 커밋 상세 순회가 오름차순이라
        중간에 멈춰도 안전하다: 워터마크는 '본 것'의 최대 시각까지만 전진하므로
        못 본 이후 커밋은 다음 실행이 이어서 수집한다(누락 0 유지).

        Returns:
            List[dict]: [{"cve_id", "commit_ts"(datetime), "is_new"(bool)}], commit_ts 오름차순.
            is_new=False → DB에 같은 content_hash로 이미 존재(재처리 불필요, 워터마크 전진엔 포함).
        """
        since_str = since_dt.astimezone(pytz.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        params_base = {"since": since_str, "per_page": 100}
        if until_dt is not None:
            params_base["until"] = until_dt.astimezone(pytz.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            logger.info(f"CVE 수집(워터마크 기반): {since_str} ~ {params_base['until']}")
        else:
            logger.info(f"CVE 수집(워터마크 기반): {since_str} 이후")

        # 1) 커밋 목록 전체 페이지네이션 (오래된 것까지 포함) — 목록은 파일 미포함이라 저비용
        commits = []
        page = 1
        while page <= max_commit_pages:
            rate_limit_manager.check_and_wait("github")
            resp = requests.get(
                "https://api.github.com/repos/CVEProject/cvelistV5/commits",
                headers=self.headers,
                params={**params_base, "page": page},
                timeout=15,
            )
            resp.raise_for_status()
            rate_limit_manager.record_call("github")
            batch = resp.json()
            if not batch:
                break
            commits.extend(batch)
            if len(batch) < 100:
                break
            page += 1
        else:
            logger.warning(f"⚠️ 커밋 페이지 상한({max_commit_pages}) 도달 — 비정상적으로 긴 공백 가능")

        if not commits:
            logger.info("신규 커밋 없음")
            return []

        # 2) 오래된 순(FIFO) 정렬
        commits.sort(key=self._commit_ts)

        # 3) 커밋별 파일 → CVE, 각 CVE의 최신 커밋 시각 매핑
        # GitHub 커밋 상세 API는 files를 페이지당 최대 300개로 자르므로, 벌크 커밋
        # (수백~수천 파일)에서 301번째 이후 CVE가 조용히 누락되지 않게 페이지네이션한다.
        cve_ts: Dict[str, datetime.datetime] = {}
        for commit in commits:
            # 소프트 데드라인: 오름차순 순회라 여기서 멈춰도 안전 (본 것까지만 워터마크 전진)
            if deadline_ts is not None and time.time() > deadline_ts:
                logger.warning("⏰ 수집 시간 예산 도달 — 지금까지 상세 조회한 커밋까지만 처리 (이후는 다음 실행)")
                break
            try:
                ts = datetime.datetime.fromisoformat(self._commit_ts(commit).replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                ts = datetime.datetime.now(pytz.UTC)
            file_page = 1
            while True:
                rate_limit_manager.check_and_wait("github")
                cr = requests.get(
                    commit["url"], headers=self.headers,
                    params={"page": file_page}, timeout=10,
                )
                cr.raise_for_status()
                rate_limit_manager.record_call("github")
                files = cr.json().get("files", []) or []
                for file_info in files:
                    cid = self._extract_cve_id(file_info.get("filename", ""))
                    if not cid:
                        continue
                    prev = cve_ts.get(cid)
                    if prev is None or ts > prev:
                        cve_ts[cid] = ts
                # 300개 미만이면 마지막 페이지 (300 = 커밋 상세 files 페이지 상한)
                if len(files) < 300:
                    break
                file_page += 1

        if not cve_ts:
            return []

        # 4) DB 중복 제거 (일반/벌크 구분 없이 전부) — content_hash 같으면 이미 처리됨
        all_ids = list(cve_ts.keys())
        existing = db.batch_get_content_hashes(all_ids) if db else {}
        result = []
        skipped = 0
        for cid, ts in cve_ts.items():
            old_hash = existing.get(cid)
            if old_hash is None:
                result.append({"cve_id": cid, "commit_ts": ts, "is_new": True})
                continue
            # 데드라인 도달 시 해시 사전검사(원문 fetch) 생략 — 보수적으로 처리 대상 취급
            # (중복 처리 가능성은 실행당 상한이 흡수, 누락 방지가 우선)
            if deadline_ts is not None and time.time() > deadline_ts:
                result.append({"cve_id": cid, "commit_ts": ts, "is_new": True})
                continue
            raw_json = self._fetch_raw_cve_json(cid)
            if raw_json is None:
                # 조회 실패 → 안전하게 처리 대상(재시도)으로 (누락 방지 우선)
                result.append({"cve_id": cid, "commit_ts": ts, "is_new": True})
                continue
            if self._compute_content_hash(raw_json) != old_hash:
                result.append({"cve_id": cid, "commit_ts": ts, "is_new": True})
            else:
                result.append({"cve_id": cid, "commit_ts": ts, "is_new": False})
                skipped += 1

        result.sort(key=lambda x: x["commit_ts"])
        new_count = len(result) - skipped
        logger.info(f"수집 결과: 후보 {len(result)}건 (신규/변경 {new_count}, 이미처리 {skipped})")
        return result
    
    def parse_affected(self, affected_list: List[Dict]) -> List[Dict]:
        """Affected 정보 파싱"""
        results = []
        
        for item in affected_list:
            vendor = item.get('vendor', 'Unknown')
            product = item.get('product', 'Unknown')
            versions = []
            patch_version = None
            
            for v in item.get('versions', []):
                version = v.get('version', '')
                less_than = v.get('lessThan', '')
                less_than_eq = v.get('lessThanOrEqual', '')
                ver_str = ""
                
                if v.get('status') == "affected":
                    if version and version not in ["0", "n/a"]:
                        ver_str += f"{version} 부터 "
                    if less_than:
                        ver_str += f"{less_than} 이전"
                        patch_version = less_than  # 이 버전 이상으로 패치
                    elif less_than_eq:
                        ver_str += f"{less_than_eq} 이하"
                        # lessThanOrEqual은 정확한 패치 버전을 알 수 없음
                    elif not less_than and not less_than_eq and version:
                        ver_str = f"{version} (단일 버전)"
                    
                    if not ver_str:
                        ver_str = "모든 버전"
                    
                    versions.append(ver_str.strip())
                
                # unaffected/fixed 상태에서 패치 버전 추출
                elif v.get('status') in ['unaffected', 'fixed'] and version:
                    if not patch_version:
                        patch_version = version
            
            results.append({
                "vendor": vendor,
                "product": product,
                "versions": ", ".join(versions) if versions else "정보 없음",
                "patch_version": patch_version
            })
        
        return results
    
    def enrich_cve(self, cve_id: str) -> Dict:
        """CVE 상세 정보 수집.

        raw.githubusercontent.com은 부하 시 느려 Read timeout이 잦다. 네트워크 오류는
        지수 백오프로 재시도하고, 최종 실패 시 state='ERROR'를 반환한다 — 호출측
        (prepare_single_cve)이 이를 'failed'로 처리해 워터마크가 붙잡고 다음 실행에서
        재수집하므로 누락되지 않는다. (기존엔 @retry가 함수 내부 except에 예외가 삼켜져
        재시도가 발동하지 않고 ERROR가 handled로 흘러 CVE가 조용히 누락됐다.)
        """
        parts = cve_id.split('-')
        year, id_num = parts[1], parts[2]
        group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"
        raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"

        json_data = None
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                rate_limit_manager.check_and_wait("github")
                response = requests.get(raw_url, timeout=20)
                if response.status_code == 404:
                    logger.warning(f"{cve_id} not found (404)")
                    return self._error_response(cve_id, state="NOT_FOUND")
                response.raise_for_status()
                rate_limit_manager.record_call("github")
                json_data = response.json()
                break
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < max_attempts:
                    wait = 2 * attempt  # 2s, 4s
                    logger.warning(f"{cve_id} 수집 일시오류({attempt}/{max_attempts}): {e} → {wait}s 후 재시도")
                    time.sleep(wait)
                    continue
                logger.error(f"{cve_id} 수집 최종 실패(네트워크) → 다음 실행 재수집")
                return self._error_response(cve_id)
            except Exception as e:
                logger.error(f"{cve_id} enrichment failed: {e}")
                return self._error_response(cve_id)

        try:
            cna = json_data.get('containers', {}).get('cna', {})

            # 콘텐츠 해시 계산 (DB 저장용)
            content_hash = self._compute_content_hash(json_data)

            data = {
                "id": cve_id,
                "title": "N/A",
                "cvss": 0.0,
                "cvss_vector": "N/A",
                "description": "N/A",
                "state": "UNKNOWN",
                "cwe": [],
                "references": [],
                "affected": [],
                "ssvc": {},
                "content_hash": content_hash
            }
            
            data['state'] = json_data.get('cveMetadata', {}).get('state', 'UNKNOWN')
            data['title'] = cna.get('title', 'N/A')
            data['affected'] = self.parse_affected(cna.get('affected', []))

            # 영어 설명 우선. lang은 'en'뿐 아니라 'en-US'/'en-GB' 등 지역 태그를 쓰는
            # CNA(Microsoft 등)가 많아 startswith('en')로 매칭한다. 영어가 없으면 첫 설명 폴백.
            descriptions = cna.get('descriptions', []) or []
            en_desc = next((d.get('value') for d in descriptions
                            if (d.get('lang') or '').lower().startswith('en') and d.get('value')), None)
            if en_desc:
                data['description'] = en_desc
            elif descriptions and descriptions[0].get('value'):
                data['description'] = descriptions[0]['value']
            
            for metric in cna.get('metrics', []):
                if 'cvssV4_0' in metric:
                    data['cvss'] = metric['cvssV4_0'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV4_0'].get('vectorString', 'N/A')
                    break
                elif 'cvssV3_1' in metric:
                    data['cvss'] = metric['cvssV3_1'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV3_1'].get('vectorString', 'N/A')
                    break
                elif 'cvssV3_0' in metric:
                    data['cvss'] = metric['cvssV3_0'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV3_0'].get('vectorString', 'N/A')
                    break
            
            for pt in cna.get('problemTypes', []):
                for desc in pt.get('descriptions', []):
                    cwe_id = desc.get('cweId', desc.get('description', ''))
                    if cwe_id:
                        data['cwe'].append(cwe_id)
            
            for ref in cna.get('references', []):
                if 'url' in ref:
                    data['references'].append(ref['url'])

            # CISA vulnrichment (ADP 컨테이너) — 이미 받은 레코드에서 파싱 (추가 네트워크 0, CC0)
            self._enrich_from_adp(json_data, data)

            logger.debug(f"Enriched {cve_id}: CVSS={data['cvss']}, State={data['state']}, SSVC={data['ssvc'].get('exploitation','-')}")
            return data

        except Exception as e:
            logger.error(f"{cve_id} 파싱 실패: {e}")
            return self._error_response(cve_id)
    
    def _enrich_from_adp(self, json_data: Dict, data: Dict) -> None:
        """CISA vulnrichment(ADP 컨테이너)에서 SSVC·CVSS·CWE 보강.

        cvelistV5 레코드에 이미 포함된 containers.adp를 파싱하므로 추가 네트워크 비용 0.
        CC0 1.0 라이선스 — 제한 없이 사용/재배포 가능 (P5 최우선 소스).
        SSVC Exploitation(none/poc/active)은 "실제 악용 중" 여부의 1급 신호.
        """
        try:
            adp_containers = json_data.get('containers', {}).get('adp', []) or []
        except AttributeError:
            return

        for container in adp_containers:
            provider = (container.get('providerMetadata') or {}).get('shortName', '')
            # CISA-ADP 컨테이너만 사용 (다른 ADP는 신뢰도/구조 상이)
            if provider != 'CISA-ADP':
                continue

            for metric in container.get('metrics', []) or []:
                # SSVC 결정 정보
                other = metric.get('other') or {}
                if other.get('type') == 'ssvc':
                    for opt in (other.get('content', {}) or {}).get('options', []) or []:
                        for key, val in opt.items():
                            data['ssvc'][key.lower().replace(' ', '_')] = val
                # CVSS 보강 (cna에 없을 때만)
                if data['cvss'] == 0.0:
                    for key in ('cvssV4_0', 'cvssV3_1', 'cvssV3_0'):
                        if key in metric:
                            data['cvss'] = metric[key].get('baseScore', 0.0)
                            data['cvss_vector'] = metric[key].get('vectorString', 'N/A')
                            logger.info(f"  ADP CVSS 보강: {data['id']} → {data['cvss']}")
                            break

            # CWE 보강 (cna에 없을 때만)
            if not data['cwe']:
                for pt in container.get('problemTypes', []) or []:
                    for desc in pt.get('descriptions', []) or []:
                        cwe_id = desc.get('cweId', '')
                        if cwe_id:
                            data['cwe'].append(cwe_id)

    # ====================================================================
    # [5] 추가 위협 인텔리전스 수집
    # ====================================================================

    def fetch_vulncheck_kev(self) -> bool:
        """VulnCheck KEV 목록 다운로드 (CISA KEV보다 커버리지 넓음)"""
        api_key = os.environ.get("VULNCHECK_API_KEY")
        if not api_key:
            logger.debug("VULNCHECK_API_KEY 미설정, VulnCheck KEV 건너뜀")
            return False
        
        try:
            rate_limit_manager.check_and_wait("vulncheck")
            
            response = requests.get(
                "https://api.vulncheck.com/v3/index/vulncheck-kev",
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
                timeout=15
            )
            response.raise_for_status()
            rate_limit_manager.record_call("vulncheck")
            
            data = response.json()
            for item in data.get('data', []):
                cve_id = item.get('cveID', '')
                if cve_id:
                    self.vulncheck_kev_set.add(cve_id)
            
            logger.info(f"VulnCheck KEV 로드: {len(self.vulncheck_kev_set)}건")
            return True
            
        except Exception as e:
            logger.warning(f"VulnCheck KEV 실패: {e}")
            return False
    
    def enrich_from_nvd(self, cve_data: Dict) -> Dict:
        """NVD에서 CVSS/CWE 보충 (CVEProject에 없을 때) + CPE 수집"""
        api_key = os.environ.get("NVD_API_KEY")
        cve_id = cve_data['id']
        # 자산 매칭용 선제 조회와 위협인텔 경로의 이중 호출 방지 플래그 ('_' 접두 → DB 미저장)
        cve_data['_nvd_enriched'] = True

        try:
            rate_limit_manager.check_and_wait("nvd")
            
            headers = {}
            if api_key:
                headers["apiKey"] = api_key
            
            response = requests.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                headers=headers, timeout=15
            )
            response.raise_for_status()
            rate_limit_manager.record_call("nvd")
            
            data = response.json()
            vulns = data.get('vulnerabilities', [])
            if not vulns:
                return cve_data
            
            cve_item = vulns[0].get('cve', {})
            metrics = cve_item.get('metrics', {})
            
            # CVSS 보충 (기존에 없을 때만)
            if cve_data['cvss'] == 0.0:
                for key in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']:
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get('cvssData', {})
                        cve_data['cvss'] = cvss_data.get('baseScore', 0.0)
                        cve_data['cvss_vector'] = cvss_data.get('vectorString', 'N/A')
                        logger.info(f"  NVD CVSS 보충: {cve_id} → {cve_data['cvss']}")
                        break
            
            # CWE 보충 (기존에 없을 때만)
            if not cve_data['cwe']:
                for weakness in cve_item.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        cwe_val = desc.get('value', '')
                        if cwe_val and cwe_val != 'NVD-CWE-noinfo':
                            cve_data['cwe'].append(cwe_val)
            
            # CPE (영향받는 제품 식별자) 추가
            cpe_list = []
            for config in cve_item.get('configurations', []):
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        if match.get('vulnerable'):
                            cpe_list.append(match.get('criteria', ''))
            if cpe_list:
                cve_data['nvd_cpe'] = cpe_list[:5]
            
            return cve_data
            
        except Exception as e:
            logger.debug(f"NVD enrichment 실패 ({cve_id}): {e}")
            return cve_data
    
    def check_poc_exists(self, cve_id: str) -> Dict:
        """PoC 존재 여부 확인 (nomi-sec → trickest/cve fallback)"""
        # 1차: nomi-sec/PoC-in-GitHub
        result = self._check_nomi_sec(cve_id)
        if result['has_poc']:
            return result

        # 2차: trickest/cve (fallback)
        result = self._check_trickest(cve_id)
        return result

    def _check_nomi_sec(self, cve_id: str) -> Dict:
        """nomi-sec/PoC-in-GitHub에서 PoC 확인 (한도 소진 시 장시간 대기 대신 SKIP)"""
        try:
            parts = cve_id.split('-')
            year = parts[1]

            if not rate_limit_manager.check_and_wait("github", max_wait=60):
                return {"has_poc": False, "poc_count": 0, "poc_urls": []}

            url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve_id}.json"
            response = requests.get(url, timeout=10)
            rate_limit_manager.record_call("github")

            if response.status_code == 200:
                poc_data = response.json()
                poc_urls = []
                if isinstance(poc_data, list):
                    poc_urls = [p.get('html_url', '') for p in poc_data[:3] if p.get('html_url')]

                logger.info(f"  🔥 PoC 발견 (nomi-sec): {cve_id} ({len(poc_urls)}개)")
                return {"has_poc": True, "poc_count": len(poc_data) if isinstance(poc_data, list) else 1, "poc_urls": poc_urls}

            return {"has_poc": False, "poc_count": 0, "poc_urls": []}

        except Exception as e:
            logger.debug(f"nomi-sec PoC 확인 실패 ({cve_id}): {e}")
            return {"has_poc": False, "poc_count": 0, "poc_urls": []}

    def _check_trickest(self, cve_id: str) -> Dict:
        """trickest/cve에서 PoC 확인 (마크다운 파일 기반)"""
        try:
            parts = cve_id.split('-')
            year = parts[1]

            url = f"https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id}.md"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                content = response.text
                # 마크다운에서 GitHub PoC URL 추출
                poc_urls = re.findall(r'https://github\.com/[^\s\)]+', content)
                poc_urls = list(dict.fromkeys(poc_urls))[:3]  # 중복 제거, 최대 3개

                logger.info(f"  🔥 PoC 발견 (trickest): {cve_id} ({len(poc_urls)}개)")
                return {"has_poc": True, "poc_count": len(poc_urls) or 1, "poc_urls": poc_urls}

            return {"has_poc": False, "poc_count": 0, "poc_urls": []}

        except Exception as e:
            logger.debug(f"trickest PoC 확인 실패 ({cve_id}): {e}")
            return {"has_poc": False, "poc_count": 0, "poc_urls": []}
    
    def check_github_advisory(self, cve_id: str) -> Dict:
        """GitHub Advisory DB에서 패키지 정보 조회.

        시간당 한도(100회) 소진 시 수십 분 대기 대신 SKIP한다 — advisory는 부가 정보
        (패키지 목록)라 없어도 리포트가 성립하고, 대기하면 파이프라인 전체(30분 타임아웃)가
        멈춰 다음 실행까지 실패시킨다. 다음 시간 윈도우의 실행에서 자연 재개."""
        try:
            if not rate_limit_manager.check_and_wait("github_advisory", max_wait=30):
                return {"has_advisory": False}
            
            response = requests.get(
                f"https://api.github.com/advisories?cve_id={cve_id}",
                headers=self.headers, timeout=10
            )
            response.raise_for_status()
            rate_limit_manager.record_call("github_advisory")
            
            advisories = response.json()
            if not advisories:
                return {"has_advisory": False}
            
            adv = advisories[0]
            packages = []
            for vuln in adv.get('vulnerabilities', []):
                pkg = vuln.get('package', {})
                if pkg:
                    packages.append({
                        "ecosystem": pkg.get('ecosystem', 'Unknown'),
                        "name": pkg.get('name', 'Unknown'),
                        "vulnerable_range": vuln.get('vulnerable_version_range', ''),
                        "patched": vuln.get('patched_versions', '')
                    })
            
            result = {
                "has_advisory": True,
                "severity": adv.get('severity', 'unknown'),
                "packages": packages[:5],
                "ghsa_id": adv.get('ghsa_id', '')
            }
            
            if packages:
                logger.info(f"  📦 GitHub Advisory 발견: {cve_id} ({len(packages)}개 패키지)")
            
            return result
            
        except Exception as e:
            logger.debug(f"GitHub Advisory 실패 ({cve_id}): {e}")
            return {"has_advisory": False}
    
    @staticmethod
    def _parse_cpe(cpe: str):
        """CPE 2.3 문자열에서 (vendor, product, version) 추출.
        형식: cpe:2.3:a:vendor:product:version:update:... — 미상/와일드카드는 제외."""
        parts = cpe.split(':')
        if len(parts) < 6 or not parts[0].startswith('cpe'):
            return None
        vendor, product, version = parts[3], parts[4], parts[5]
        if vendor in ('', '*', '-') or product in ('', '*', '-'):
            return None
        return vendor, product, version

    def _augment_affected_from_cpe(self, cve_data: Dict) -> Dict:
        """CVE 자체 affected에 유효한 벤더가 없을 때 NVD CPE로 벤더/제품을 보강한다.
        자산 매칭(is_target_asset)이 affected를 1차 소스로 쓰므로 매칭 누락 방지에 직접 기여."""
        cpes = cve_data.get('nvd_cpe') or []
        if not cpes:
            return cve_data
        existing = cve_data.get('affected', [])
        has_valid_vendor = any(
            (a.get('vendor', '').lower() not in ('', 'unknown', 'n/a')) for a in existing
        )
        if has_valid_vendor:
            return cve_data  # CVE 자체 데이터 우선
        seen, derived = set(), []
        for cpe in cpes:
            parsed = self._parse_cpe(cpe)
            if not parsed:
                continue
            vendor, product, version = parsed
            key = (vendor.lower(), product.lower())
            if key in seen:
                continue
            seen.add(key)
            derived.append({
                "vendor": vendor.replace('_', ' '),
                "product": product.replace('_', ' '),
                "versions": version if version not in ('*', '-', '') else "정보 없음",
                "patch_version": None,
            })
        if derived:
            cve_data['affected'] = derived
            logger.info(f"  📦 NVD CPE로 영향자산 보강: {cve_data['id']} ({len(derived)}건)")
        return cve_data

    def enrich_cheap_signals(self, cve_data: Dict) -> Dict:
        """값싼 위험 신호만 보강 — 메모리 세트/캐시 인덱스 조회 (네트워크 호출 0).
        위험도 사전판별에 필요한 신호(VulnCheck KEV, ExploitDB, Metasploit)를 채운다.
        고위험 여부를 값비싼 위협인텔 전에 판정해 저위험을 값싸게 처리하기 위함."""
        cve_id = cve_data['id']
        # VulnCheck KEV (이미 fetch한 세트에서 조회 — 메모리)
        cve_data['is_vulncheck_kev'] = cve_id in self.vulncheck_kev_set
        # ExploitDB 공개 익스플로잇 (캐시 인덱스 조회). PoC 원문은 재게시하지 않고
        # 링크만 리포트에 싣는다(불변 원칙 8-②) — EDB-ID로 공식 페이지 URL 구성.
        edb_entry = enrichment_sources.exploitdb_entry(cve_id)
        cve_data['has_public_exploit'] = edb_entry is not None
        if edb_entry and edb_entry[1]:
            cve_data['_exploit_db_url'] = f"https://www.exploit-db.com/exploits/{edb_entry[1]}"
        # Metasploit 모듈 (캐시 인덱스 조회, "무기화됨" 신호, BSD-3-Clause)
        msf_modules = enrichment_sources.metasploit_modules(cve_id)
        cve_data['has_metasploit_module'] = bool(msf_modules)
        cve_data['metasploit_modules'] = [m['fullname'] for m in msf_modules[:3]]
        if msf_modules:
            logger.info(f"  🧨 Metasploit 모듈: {cve_id} ({len(msf_modules)}개, 최고 rank={msf_modules[0]['rank_name']})")
        return cve_data

    def enrich_threat_intel(self, cve_data: Dict) -> Dict:
        """값비싼 위협 인텔리전스 풀 수집 (NVD + PoC + Advisory, 네트워크 다중 호출).
        고위험 CVE에만 호출 — 저위험은 enrich_cheap_signals만으로 충분(처리량 확보).
        enrich_cve() + enrich_cheap_signals() 이후에 호출."""
        cve_id = cve_data['id']
        logger.info(f"위협 인텔리전스 수집(고위험): {cve_id}")

        # 값싼 신호가 아직 없으면 채운다 (직접 호출 대비)
        if 'has_public_exploit' not in cve_data:
            self.enrich_cheap_signals(cve_data)

        # 1. NVD CVSS/CWE 보충 → CPE로 영향자산(벤더/제품) 보강 (자산 매칭 누락 방지)
        #    자산 매칭 단계에서 이미 선제 조회했으면 재호출 생략
        if not cve_data.get('_nvd_enriched'):
            cve_data = self.enrich_from_nvd(cve_data)
        cve_data = self._augment_affected_from_cpe(cve_data)

        # 2. PoC 존재 여부 (nomi-sec → trickest 네트워크 검색)
        poc_info = self.check_poc_exists(cve_id)
        cve_data['has_poc'] = poc_info['has_poc']
        cve_data['poc_count'] = poc_info['poc_count']
        cve_data['poc_urls'] = poc_info['poc_urls']

        # 3. GitHub Advisory (네트워크)
        cve_data['github_advisory'] = self.check_github_advisory(cve_id)

        return cve_data
    
    def _error_response(self, cve_id: str, state: str = "ERROR") -> Dict:
        """수집 실패 응답. state="ERROR"(네트워크 등 일시 실패 → 호출측이 재수집 대상으로
        처리) / "NOT_FOUND"(404 — 레코드 없음, 재수집 무의미 → handled로 통과)."""
        return {
            "id": cve_id,
            "title": "Error",
            "cvss": 0.0,
            "cvss_vector": "N/A",
            "description": "Error",
            "state": state,
            "cwe": [],
            "references": [],
            "affected": []
        }