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

class CollectorError(Exception):
    """데이터 수집 관련 에러"""
    pass

class Collector:
    # 벌크 메인테넌스 커밋 감지 패턴
    BULK_PATTERNS = re.compile(
        r'(format|standardize|normalize|batch|bulk|automated|metadata|date.?time|migration|mass.?update|reformat)',
        re.IGNORECASE
    )

    def __init__(self):
        self.kev_set: Set[str] = set()
        self.vulncheck_kev_set: Set[str] = set()
        self.epss_cache: Dict[str, float] = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }
        # config import는 순환 참조 방지를 위해 지연
        try:
            from config import config
            self.bulk_threshold = config.PERFORMANCE.get("bulk_commit_threshold", 100)
        except Exception:
            self.bulk_threshold = 100
    
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
            self.kev_set = {vuln['cveID'] for vuln in data.get('vulnerabilities', [])}
            
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

    def _is_bulk_commit(self, commit_detail: dict) -> bool:
        """벌크 메인테넌스 커밋인지 감지.

        조건: 파일 수가 threshold 이상이면 벌크로 간주.
        커밋 메시지에 벌크 패턴이 있으면 추가 확신.
        """
        files = commit_detail.get('files', [])
        file_count = len(files)
        message = commit_detail.get('commit', {}).get('message', '')

        # 파일 수만으로 벌크 판단 (threshold 이상이면 항상 벌크)
        if file_count >= self.bulk_threshold:
            if self.BULK_PATTERNS.search(message):
                logger.info(f"벌크 커밋 감지: {file_count}개 파일, 메시지 패턴 매칭")
            else:
                logger.info(f"벌크 커밋 감지: {file_count}개 파일 (대량 수정)")
            return True

        return False

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
            response = requests.get(raw_url, timeout=10)
            response.raise_for_status()

            return response.json()
        except Exception as e:
            logger.debug(f"{cve_id} raw JSON 조회 실패: {e}")
            return None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_recent_cves(self, hours: int = 2, db=None) -> List[dict]:
        """GitHub CVEProject에서 최근 CVE 수집 (스마트 필터링).

        3단계 필터링:
        1. 커밋에서 CVE ID 추출 + 벌크 커밋 감지
        2. 일반 커밋 CVE → 전부 처리 대상
        3. 벌크 커밋 CVE → 콘텐츠 해시 비교 → 메타데이터만 변경된 것 스킵

        Returns:
            List[dict]: [{"cve_id": str, "is_new": bool}, ...]
        """
        now = datetime.datetime.now(pytz.UTC)
        since_str = (now - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

        url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?since={since_str}"

        try:
            rate_limit_manager.check_and_wait("github")
            logger.info(f"Fetching CVEs from last {hours} hours...")

            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            rate_limit_manager.record_call("github")

            commits = response.json()

            seen = set()
            normal_cve_ids = []
            bulk_cve_ids = []
            result = []
            skipped = 0

            # Phase 1: 모든 커밋에서 CVE ID 수집 + 벌크 여부 태깅
            for commit in commits:
                rate_limit_manager.check_and_wait("github")

                commit_response = requests.get(commit['url'], headers=self.headers, timeout=10)
                commit_response.raise_for_status()
                rate_limit_manager.record_call("github")

                commit_detail = commit_response.json()
                is_bulk = self._is_bulk_commit(commit_detail)

                for file_info in commit_detail.get('files', []):
                    cve_id = self._extract_cve_id(file_info['filename'])
                    if not cve_id or cve_id in seen:
                        continue
                    seen.add(cve_id)

                    if is_bulk:
                        bulk_cve_ids.append(cve_id)
                    else:
                        normal_cve_ids.append(cve_id)

            # Phase 2: 일반 커밋 CVE → 전부 처리 대상
            for cve_id in normal_cve_ids:
                result.append({"cve_id": cve_id, "is_new": True})

            # Phase 3: 벌크 커밋 CVE → 배치 해시 비교로 필터링
            if bulk_cve_ids:
                if db:
                    existing_hashes = db.batch_get_content_hashes(bulk_cve_ids)
                    logger.info(f"벌크 커밋 CVE {len(bulk_cve_ids)}건 중 DB 해시 {len(existing_hashes)}건 발견")

                    for cve_id in bulk_cve_ids:
                        old_hash = existing_hashes.get(cve_id)
                        if old_hash is None:
                            # DB에 없음 → 신규 CVE, 반드시 처리
                            result.append({"cve_id": cve_id, "is_new": True})
                            continue

                        # DB에 있음 → raw JSON 가져와서 해시 비교
                        raw_json = self._fetch_raw_cve_json(cve_id)
                        if raw_json is None:
                            continue
                        new_hash = self._compute_content_hash(raw_json)
                        if new_hash != old_hash:
                            result.append({"cve_id": cve_id, "is_new": False})
                        else:
                            skipped += 1
                else:
                    # DB 없으면 벌크 커밋도 모두 처리
                    for cve_id in bulk_cve_ids:
                        result.append({"cve_id": cve_id, "is_new": True})

            logger.info(f"스마트 필터링 결과: {len(result)}건 처리 대상 "
                       f"(일반 {len(normal_cve_ids)}건, 벌크 {len(bulk_cve_ids)}건 중 {skipped}건 스킵)")
            return result

        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in fetch_recent_cves: {e}")
            return []
    
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
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5)
    )
    def enrich_cve(self, cve_id: str) -> Dict:
        """CVE 상세 정보 수집"""
        try:
            rate_limit_manager.check_and_wait("github")
            
            parts = cve_id.split('-')
            year, id_num = parts[1], parts[2]
            group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"
            
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            
            response = requests.get(raw_url, timeout=10)
            response.raise_for_status()
            rate_limit_manager.record_call("github")
            
            json_data = response.json()
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
                "content_hash": content_hash
            }
            
            data['state'] = json_data.get('cveMetadata', {}).get('state', 'UNKNOWN')
            data['title'] = cna.get('title', 'N/A')
            data['affected'] = self.parse_affected(cna.get('affected', []))
            
            for desc in cna.get('descriptions', []):
                if desc.get('lang') == 'en':
                    data['description'] = desc.get('value', 'N/A')
                    break
            
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
            
            logger.debug(f"Enriched {cve_id}: CVSS={data['cvss']}, State={data['state']}")
            return data
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"{cve_id} not found (404)")
            else:
                logger.error(f"{cve_id} HTTP error: {e}")
            return self._error_response(cve_id)
        except Exception as e:
            logger.error(f"{cve_id} enrichment failed: {e}")
            return self._error_response(cve_id)
    
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
        """NVD에서 CVSS/CWE 보충 (CVEProject에 없을 때)"""
        api_key = os.environ.get("NVD_API_KEY")
        cve_id = cve_data['id']
        
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
        """nomi-sec/PoC-in-GitHub에서 PoC 확인"""
        try:
            parts = cve_id.split('-')
            year = parts[1]

            rate_limit_manager.check_and_wait("github")

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
        """GitHub Advisory DB에서 패키지 정보 조회"""
        try:
            rate_limit_manager.check_and_wait("github_advisory")
            
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
    
    def enrich_threat_intel(self, cve_data: Dict) -> Dict:
        """
        추가 위협 인텔리전스 통합 (NVD + PoC + VulnCheck + Advisory)
        enrich_cve() 이후에 호출
        """
        cve_id = cve_data['id']
        logger.info(f"위협 인텔리전스 수집: {cve_id}")
        
        # 1. NVD CVSS/CWE 보충
        cve_data = self.enrich_from_nvd(cve_data)
        
        # 2. PoC 존재 여부
        poc_info = self.check_poc_exists(cve_id)
        cve_data['has_poc'] = poc_info['has_poc']
        cve_data['poc_count'] = poc_info['poc_count']
        cve_data['poc_urls'] = poc_info['poc_urls']
        
        # 3. VulnCheck KEV (이미 fetch한 세트에서 조회)
        cve_data['is_vulncheck_kev'] = cve_id in self.vulncheck_kev_set
        
        # 4. GitHub Advisory
        advisory = self.check_github_advisory(cve_id)
        cve_data['github_advisory'] = advisory
        
        return cve_data
    
    def _error_response(self, cve_id: str) -> Dict:
        """에러 발생 시 기본 응답"""
        return {
            "id": cve_id,
            "title": "Error",
            "cvss": 0.0,
            "cvss_vector": "N/A",
            "description": "Error",
            "state": "ERROR",
            "cwe": [],
            "references": [],
            "affected": []
        }