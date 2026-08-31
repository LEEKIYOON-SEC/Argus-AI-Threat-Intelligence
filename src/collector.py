"""CVE 레코드 해석과 위협 신호 보강.

'무엇이 바뀌었는지'는 feed.py가, '얼마나 위험한지'는 risk.py가, '진행 지점'은 state.py가
맡는다. 여기 남은 일은 하나다 — **레코드 한 건을 우리 형식의 상태 dict로 바꾸고,
거기에 외부 위협 신호를 붙이는 것**.

예전에는 여기서 GitHub 커밋 API를 순회하고(최대 300페이지) CVE마다 원문을 받아 콘텐츠
해시를 비교했다. 그 경로는 feed.py의 delta 피드가 통째로 대체했다 — 변경 발견이 1 요청이라
해시 사전대조 자체가 필요 없어졌다(피드가 new/updated를 직접 알려준다).
"""
import os
import re
import time
from typing import Dict, List, Optional, Set, Tuple

import requests
from tenacity import retry, stop_after_attempt, wait_exponential

import ai_provenance
import enrichment_sources
import feed
from logger import logger
from rate_limiter import rate_limit_manager


class CollectorError(Exception):
    """데이터 수집 관련 에러"""
    pass

# ─────────────────────────────────────────────
# NVD CPE → 영향 벤더/제품
# 대시보드의 벤더·제품 필터가 이 값을 쓴다. 수집 경로와 소급 백필(backfill_vendors)이
# 같은 규칙을 써야 해서 모듈 레벨에 둔다.
# ─────────────────────────────────────────────
def parse_cpe(cpe: str) -> Optional[Tuple[str, str, str]]:
    """CPE 2.3에서 (vendor, product, version). 미상/와일드카드는 쓸 수 없어 버린다.
    형식: cpe:2.3:<part>:<vendor>:<product>:<version>:..."""
    parts = str(cpe or '').split(':')
    if len(parts) < 6 or not parts[0].startswith('cpe'):
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if vendor in ('', '*', '-') or product in ('', '*', '-'):
        return None
    return vendor, product, version


def _meaningful(v) -> str:
    """표시할 값이 있으면 그 값, 없으면 ''. CNA가 넣는 자리표시자를 걸러낸다."""
    s = str(v or '').strip()
    return '' if s.lower() in ('', 'unknown', 'n/a', '-', 'n/a (단일 버전)', '정보 없음') else s


def _key(s: str) -> str:
    """제품명 비교용 정규화 — CPE는 'postgresql', CNA는 'PostgreSQL'로 쓴다."""
    return re.sub(r'[\s_-]+', '', str(s or '').lower())


def affected_from_cpes(cpes: List[str], existing: List[Dict] = None,
                       limit: int = 5) -> List[Dict]:
    """CPE 목록 → affected 항목. 기존 항목이 있으면 덮어쓰지 않고 벤더만 채운다.

    통째로 갈아끼우면 CNA가 준 정보를 잃는다. 실측으로 벤더 없는 198건 중 119건이
    제품명과 상세 버전 범위를 갖고 있었다 — 예를 들어

        product='PostgreSQL'  versions='18 부터 18.5 이전, 17 부터 17.11 이전, ...'

    이걸 CPE 유래 항목(versions='정보 없음')으로 바꾸면 벤더 하나를 얻고 버전 범위를
    통째로 버리는 셈이다. 그래서 제품명이 있는 항목은 그대로 두고 벤더만 채운다.
    제품명조차 없는 항목(vendor/product 모두 n/a)만 CPE 유래 항목으로 대체한다."""
    seen, derived = set(), []
    for cpe in cpes or []:
        parsed = parse_cpe(cpe)
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
        if len(derived) >= limit:
            break
    if not derived:
        return []

    keepers = [a for a in (existing or []) if isinstance(a, dict) and _meaningful(a.get('product'))]
    if not keepers:
        return derived      # 살릴 게 없으면 CPE 유래로 채운다

    # 제품명이 맞는 CPE에서 벤더를 가져온다. 못 찾으면 CPE 벤더가 하나뿐일 때만
    # 그것을 쓴다 — 여러 벤더 중 아무거나 붙이면 틀린 벤더를 심는 셈이다.
    by_product = {_key(d['product']): d['vendor'] for d in derived}
    vendors = {d['vendor'] for d in derived}
    sole = next(iter(vendors)) if len(vendors) == 1 else ''
    out = []
    for a in keepers:
        vendor = by_product.get(_key(a.get('product'))) or sole
        out.append({**a, "vendor": vendor} if vendor else dict(a))
    # CNA가 언급하지 않은 제품이 CPE에 더 있으면 뒤에 덧붙인다 (버리지 않는다)
    known = {_key(a.get('product')) for a in keepers}
    out.extend(d for d in derived if _key(d['product']) not in known)
    return out[:limit]


class Collector:
    def __init__(self):
        self.kev_set: Set[str] = set()
        self.kev_date_added: Dict[str, str] = {}  # CVE → KEV 등재일 (gap-filler용)
        self.kev_ransomware: Set[str] = set()     # KEV 중 랜섬웨어 캠페인 사용 확인분
        self.kev_due_date: Dict[str, str] = {}    # CVE → CISA 조치 기한
        # Anthropic 공개 레저 (CVE → ANT ID). bulk-lane이 적재해 넣어 준다.
        # 2.3MB라 5분 주기에는 무거워, fast-lane은 레코드 크레딧 경로만 쓴다.
        self.ai_ledger: Optional[Dict[str, Dict]] = None
        self.vulncheck_kev_set: Set[str] = set()
        self.epss_cache: Dict[str, float] = {}
        # percentile 을 따로 든다. 절대 점수는 EPSS 모델이 갱신되면 같은 값의 의미가
        # 달라지지만 percentile 은 분포 기준이라 그렇지 않다 (risk.py 주석 참조).
        self.epss_percentile: Dict[str, float] = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    def fetch_kev(self) -> bool:
        """CISA KEV 목록 적재. 실제 다운로드는 enrichment_sources가 한다.

        같은 실행 안에서 스냅샷 대조(signal_snapshot)도 KEV 전량을 쓰므로, 로더를 한
        곳으로 모아 캐시를 공유한다 — 예전에는 여기서 따로 받아 같은 파일을 두 번 받았다.
        """
        data = enrichment_sources.load_cisa_kev()
        if data is None:
            logger.error("KEV 적재 실패 — 이번 실행은 KEV 신호 없이 진행")
            return False

        self.kev_set = set(data)
        self.kev_date_added = {cid: item.get('dateAdded', '') for cid, item in data.items()}
        # 랜섬웨어 캠페인에 실제로 쓰인 것 — 같은 KEV라도 대응 순서를 가르는 축이다.
        self.kev_ransomware = {
            cid for cid, item in data.items()
            if str(item.get('knownRansomwareCampaignUse', '')).strip().lower() == 'known'
        }
        # 조치 기한 — CISA가 연방기관에 부여하는 마감일. 우리에게 법적 구속력은 없지만
        # "이 정도로 급하다고 본다"는 공식 판단이라 알림에 그대로 싣는다.
        self.kev_due_date = {cid: item.get('dueDate', '') for cid, item in data.items()}
        logger.info(f"KEV {len(self.kev_set)}건 적재 "
                    f"(랜섬웨어 사용 확인 {len(self.kev_ransomware)}건)")
        return True

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
                    if not cve_id:
                        continue
                    self.epss_cache[cve_id] = float(item.get('epss', 0.0) or 0.0)
                    self.epss_percentile[cve_id] = float(item.get('percentile', 0.0) or 0.0)
                
                logger.debug(f"EPSS batch {chunk_num}/{total_chunks} complete")
                
            except Exception as e:
                logger.warning(f"EPSS batch {chunk_num} failed: {e}")
                continue
        
        return self.epss_cache
    
    def parse_affected(self, affected_list: List[Dict]) -> List[Dict]:
        """Affected 정보 파싱"""
        results = []
        
        for item in affected_list:
            # cvelistV5에는 "vendor": null 처럼 값이 명시적 null인 레코드가 있다.
            # dict.get(k, 기본값)은 '키가 없을 때'만 기본값을 주므로 None이 그대로 흘러가,
            # 표시·필터 쪽에서 .lower() 호출로 AttributeError가 나 그 CVE가 매번 실패한다.
            # → 여기서 문자열로 정규화해 모든 소비자(매칭·리포트·대시보드)를 한 번에 보호.
            vendor = item.get('vendor') or 'Unknown'
            product = item.get('product') or 'Unknown'
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
        """CVE ID만 아는 상황에서 레코드를 받아 해석한다 (스냅샷 대조 경로).

        평소 경로(fast-lane)는 feed가 이미 레코드를 들고 있으므로 parse_record를 직접
        부른다 — 같은 파일을 두 번 받지 않기 위해서다.

        raw.githubusercontent.com은 부하 시 느려 Read timeout이 잦다. 네트워크 오류는
        지수 백오프로 재시도하고, 최종 실패 시 state='ERROR'를 반환한다 — 호출측이
        이를 'failed'로 처리해 워터마크가 붙잡고 다음 실행에서 재수집하므로 누락되지 않는다.
        """
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                record = feed.fetch_record(cve_id)
                if record is None:
                    # 404는 재시도해도 같다 — 재수집 대상으로 붙잡아 둘 이유가 없다
                    return self._error_response(cve_id, state="NOT_FOUND")
                return self.parse_record(cve_id, record)
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
        return self._error_response(cve_id)

    def parse_record(self, cve_id: str, json_data: Dict) -> Dict:
        """cvelistV5 레코드 원문 → 우리 형식의 상태 dict. **네트워크를 쓰지 않는다.**

        feed가 delta ZIP으로 통째로 받아 온 레코드를 그대로 넘길 수 있게 분리했다.
        """
        try:
            cna = json_data.get('containers', {}).get('cna', {})

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
                "published": "",
                # 레코드를 할당한 CNA. 점수가 아직 없는 신규 CVE를 지켜볼지 정하는 데 쓴다
                # (risk.MAJOR_CNAS) — 경계 장비 벤더는 점수보다 KEV가 먼저 오는 일이 잦다.
                "assigner": "",
                # 발견자 크레딧 — ai_provenance가 'AI가 찾았는가'를 여기서 읽는다
                "credits": [],
            }

            meta = json_data.get('cveMetadata', {}) or {}
            data['state'] = meta.get('state', 'UNKNOWN')
            data['assigner'] = str(meta.get('assignerShortName') or '').strip()
            # CVE 공개일 — 우리가 확인한 날짜(updated_at)와 별개다. 백로그를 몰아 처리하면
            # 확인일 기준 집계가 그날 하루에 몰려 실제 공개 추이를 왜곡하므로, 추이 차트는
            # 이 값을 쓴다. (표·필터·정렬은 '우리가 확인한 날' 기준을 그대로 유지)
            data['published'] = str(meta.get('datePublished') or '')[:10]
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

            # 제목: CNA title → (없으면) affected 벤더/제품 → (없으면) 설명 첫 문장.
            # Oracle 등 title 없는 CNA에서 'N/A'가 번역기로 흘러 '해당 없음' 제목이 되는 것 방지.
            title = (cna.get('title') or '').strip()
            if not title:
                aff0 = next((a for a in data['affected']
                             if a.get('product') and a['product'].lower() not in ('n/a', 'unknown')), None)
                if aff0:
                    vendor = (aff0.get('vendor') or '').strip()
                    product = aff0['product'].strip()
                    # "Oracle Corporation Oracle Coherence" 같은 중복 방지 — 제품명에 벤더가 이미 있으면 생략
                    use_vendor = vendor and vendor.lower() not in ('n/a', 'unknown') \
                        and vendor.split()[0].lower() not in product.lower()
                    title = f"{vendor} {product} vulnerability" if use_vendor else f"{product} vulnerability"
                elif data['description'] != 'N/A':
                    title = data['description'].split('. ')[0][:110]
            data['title'] = title or 'N/A'
            
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
            
            # CWE는 반드시 'CWE-숫자' 형식만 수집한다. Oracle 등 일부 CNA는 cweId 없이
            # description에 영향 설명 문장만 넣는데, 이를 폴백으로 담으면 '취약점 유형'에
            # 영문 문단이 통째로 노출되고, cwe가 채워진 것으로 오인되어 CISA-ADP의
            # 정상 CWE 보강(_enrich_from_adp의 'cna에 없을 때만' 조건)까지 막힌다.
            # description 텍스트 안에 'CWE-79' 형태로 박아 넣는 CNA는 패턴 추출로 수용.
            for pt in cna.get('problemTypes', []):
                for desc in pt.get('descriptions', []):
                    for field in (desc.get('cweId', ''), desc.get('description', '')):
                        for m in re.findall(r'CWE-\d{1,4}\b', str(field)):
                            if m not in data['cwe']:
                                data['cwe'].append(m)
            
            for ref in cna.get('references', []):
                if 'url' in ref:
                    data['references'].append(ref['url'])

            # 크레딧(발견자) — 'AI가 찾은 취약점' 판별에 쓴다. 소스를 새로 붙일 필요가 없는
            # 이유가 여기다: 우리가 이미 받는 레코드 안에 들어 있다 (실측 15% 보유).
            for credit in cna.get('credits', []) or []:
                value = str((credit or {}).get('value') or '').strip()
                if value:
                    data['credits'].append(value)

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
        """VulnCheck KEV 적재 (CISA KEV보다 넓고 대체로 이르다).

        무료지만 **출처 표기 의무**가 있는 소스다 — 이 신호로 알림이 나갈 때 'VulnCheck KEV'를
        반드시 함께 싣는다(notifier·리포트에서 처리). 키가 없으면 조용히 건너뛴다."""
        data = enrichment_sources.load_vulncheck_kev()
        if data is None:
            return False
        self.vulncheck_kev_set = set(data)
        logger.info(f"VulnCheck KEV {len(self.vulncheck_kev_set)}건 적재")
        return True

    def enrich_from_nvd(self, cve_data: Dict) -> Dict:
        """NVD에서 CVSS/CWE 보충 (CVEProject에 없을 때) + CPE 수집"""
        api_key = os.environ.get("NVD_API_KEY")
        cve_id = cve_data['id']
        # 이중 호출 방지 플래그 ('_' 접두라 DB 저장에서 자동 제외)
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
    

    def fill_affected_from_nvd(self, cve_data: Dict) -> Dict:
        """벤더가 비어 있으면 NVD를 조회해 affected(벤더/제품)를 채운다.

        NVD 조회와 CPE 보강은 항상 같이 다닌다 — 조회만 하고 보강을 안 하면 nvd_cpe만
        들고 affected는 n/a로 남는다. 실제로 그 상태였고, 보강이 고위험 전용 경로에만
        있어서 추적 CVE의 1.6%가 벤더 없이 남았다(실측 198건)."""
        if not cve_data.get('_nvd_enriched'):
            cve_data = self.enrich_from_nvd(cve_data)
        return self._augment_affected_from_cpe(cve_data)

    def _augment_affected_from_cpe(self, cve_data: Dict) -> Dict:
        """CVE 자체 affected에 유효한 벤더가 없을 때 NVD CPE로 벤더/제품을 보강한다.
        벤더가 비면 대시보드 벤더 필터에서 통째로 빠지므로 표시 품질에 직접 기여한다."""
        cpes = cve_data.get('nvd_cpe') or []
        if not cpes:
            return cve_data
        existing = cve_data.get('affected') or []
        has_valid_vendor = any(
            str(a.get('vendor') or '').lower() not in ('', 'unknown', 'n/a') for a in existing
        )
        if has_valid_vendor:
            return cve_data  # CVE 자체 데이터 우선
        derived = affected_from_cpes(cpes, existing)
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
        # KEV 중 랜섬웨어 캠페인 사용 확인분 (KEV JSON에 포함된 필드 — 추가 호출 0)
        cve_data['is_kev_ransomware'] = cve_id in self.kev_ransomware
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
        # nuclei 템플릿 (캐시 인덱스 조회, MIT). 템플릿이 있다는 건 "공격 조건이 재현
        # 가능한 형태로 정리돼 누구나 대량 스캔할 수 있다"는 뜻이라 무기화 신호로 쓴다.
        # 원문은 재게시하지 않고 저장소 링크만 싣는다(불변 원칙 8-②와 같은 취급).
        tpl = enrichment_sources.nuclei_template(cve_id)
        cve_data['has_nuclei_template'] = tpl is not None
        if tpl:
            cve_data['nuclei_severity'] = tpl.get('severity', '')
            cve_data['_nuclei_url'] = enrichment_sources.nuclei_template_url(tpl.get('path', ''))
            logger.info(f"  🎯 nuclei 템플릿: {cve_id} ({tpl.get('severity', '?')})")
        # AI가 찾은 취약점 — Anthropic 공개 레저(구조화) 우선, 없으면 레코드 크레딧.
        # 레저는 bulk-lane이 적재해 넘겨준다(2.3MB라 5분 주기에는 무겁다). 없으면
        # 크레딧 경로만 도는데, 그쪽은 레코드에 이미 들어 있어 비용이 0이다.
        prov = ai_provenance.detect(cve_id, cve_data.get('credits'), self.ai_ledger)
        if prov:
            cve_data.update(prov.as_state())
            logger.info(f"  🤖 AI 발견: {cve_id} ({prov.program}) — {prov.detail[:80]}")
        else:
            cve_data['ai_discovered'] = False
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

        # 1. NVD CVSS/CWE 보충 → CPE로 영향 벤더/제품 보강 (대시보드 필터 품질)
        #    이미 조회했으면 재호출 생략
        cve_data = self.fill_affected_from_nvd(cve_data)

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