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
    pass

def parse_cpe(cpe: str) -> Optional[Tuple[str, str, str]]:
    parts = str(cpe or '').split(':')
    if len(parts) < 6 or not parts[0].startswith('cpe'):
        return None
    vendor, product, version = parts[3], parts[4], parts[5]
    if vendor in ('', '*', '-') or product in ('', '*', '-'):
        return None
    return vendor, product, version


def _meaningful(v) -> str:
    s = str(v or '').strip()
    return '' if s.lower() in ('', 'unknown', 'n/a', '-', 'n/a (단일 버전)', '정보 없음') else s


def _key(s: str) -> str:
    return re.sub(r'[\s_-]+', '', str(s or '').lower())


def affected_from_cpes(cpes: List[str], existing: List[Dict] = None,
                       limit: int = 5) -> List[Dict]:
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
        return derived

    by_product = {_key(d['product']): d['vendor'] for d in derived}
    vendors = {d['vendor'] for d in derived}
    sole = next(iter(vendors)) if len(vendors) == 1 else ''
    out = []
    for a in keepers:
        vendor = by_product.get(_key(a.get('product'))) or sole
        out.append({**a, "vendor": vendor} if vendor else dict(a))
    known = {_key(a.get('product')) for a in keepers}
    out.extend(d for d in derived if _key(d['product']) not in known)
    return out[:limit]


_CVSS_KEYS = (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"))


def collect_cvss(containers) -> dict:
    """레코드의 모든 CVSS 를 버전별로 모은다 → {"3.1": (9.8, "CVSS:3.1/..."), …}

    예전에는 metrics 를 돌면서 4.0 을 만나면 바로 break 했다. 그런데 4.0 과 3.x 는
    산식이 달라 점수가 자주 어긋난다 — 실측(203건) **20.7%가 다르다.**
    CVE-2026-82703 은 4.0=5.1 인데 3.1=6.6, CVE-2026-82954 는 4.0=9.4 / 3.1=9.9 다.
    그런데 화면에는 어느 버전인지 표시도 없어서, NVD 에서 9.8 을 본 사람이 우리 화면의
    다른 숫자를 보면 무슨 일인지 알 수가 없다. 그래서 전부 모아 두고 함께 보여준다.
    """
    found = {}
    for container in containers:
        if not isinstance(container, dict):
            continue
        for metric in (container.get("metrics") or []):
            if not isinstance(metric, dict):
                continue
            for key, label in _CVSS_KEYS:
                blk = metric.get(key)
                if not isinstance(blk, dict):
                    continue
                score = blk.get("baseScore")
                if score is None:
                    continue
                try:
                    score = float(score)
                except (TypeError, ValueError):
                    continue
                found.setdefault(label, (score, blk.get("vectorString") or "N/A"))
    return found


def pick_cvss(found: dict):
    """(점수, 벡터, 버전). **가장 높은 점수**를 쓴다.

    낮춰 부르지 않는다는 원칙을 그대로 따른다 — 판정에 쓰는 값이 4.0 이라는 이유로
    3.x 보다 낮으면, 같은 취약점을 남들보다 안전하다고 말하는 셈이다.
    점수가 같으면 최신 버전(4.0)을 쓴다.
    """
    if not found:
        return 0.0, "N/A", ""
    order = {"4.0": 0, "3.1": 1, "3.0": 2}
    label = min(found, key=lambda k: (-found[k][0], order.get(k, 9)))
    return found[label][0], found[label][1], label


class Collector:
    def __init__(self):
        self.kev_set: Set[str] = set()
        self.kev_date_added: Dict[str, str] = {}
        self.kev_ransomware: Set[str] = set()
        self.kev_due_date: Dict[str, str] = {}
        self.kev_product: Dict[str, Tuple[str, str]] = {}
        self.ai_ledger: Optional[Dict[str, Dict]] = None
        self.vulncheck_kev_set: Set[str] = set()
        self.epss_cache: Dict[str, float] = {}
        self.epss_percentile: Dict[str, float] = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    def fetch_kev(self) -> bool:
        data = enrichment_sources.load_cisa_kev()
        if data is None:
            logger.error("KEV 적재 실패 — 이번 실행은 KEV 신호 없이 진행")
            return False

        self.kev_set = set(data)
        self.kev_date_added = {cid: item.get('dateAdded', '') for cid, item in data.items()}
        self.kev_ransomware = {
            cid for cid, item in data.items()
            if str(item.get('knownRansomwareCampaignUse', '')).strip().lower() == 'known'
        }
        self.kev_due_date = {cid: item.get('dueDate', '') for cid, item in data.items()}
        # CISA 가 정리해 둔 벤더/제품. 옛날 CVE 레코드는 affected 블록이 없어
        # vendor/product 가 'n/a' 인 경우가 많은데(KEV 무작위 60건 중 42%),
        # 하필 그게 지금 악용 중인 것들이라 화면에서 제품으로 찾을 수가 없었다.
        # KEV 쪽 표기는 사람이 정리한 것이라 깨끗하다.
        self.kev_product = {
            cid: (str(item.get('vendorProject') or '').strip(),
                  str(item.get('product') or '').strip())
            for cid, item in data.items()
        }
        logger.info(f"KEV {len(self.kev_set)}건 적재 "
                    f"(랜섬웨어 사용 확인 {len(self.kev_ransomware)}건)")
        return True

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_epss(self, cve_ids: List[str]) -> Dict[str, float]:
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
        results = []
        
        for item in affected_list:
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
                        patch_version = less_than
                    elif less_than_eq:
                        ver_str += f"{less_than_eq} 이하"
                    elif not less_than and not less_than_eq and version:
                        ver_str = f"{version} (단일 버전)"
                    
                    if not ver_str:
                        ver_str = "모든 버전"
                    
                    versions.append(ver_str.strip())
                
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
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                record = feed.fetch_record(cve_id)
                if record is None:
                    return self._error_response(cve_id, state="NOT_FOUND")
                return self.parse_record(cve_id, record)
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
                if attempt < max_attempts:
                    wait = 2 * attempt
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
        try:
            cna = json_data.get('containers', {}).get('cna', {})

            data = {
                "id": cve_id,
                "title": "N/A",
                "cvss": 0.0,
                "cvss_vector": "N/A",
                "cvss_version": "",
                "cvss_scores": {},
                "description": "N/A",
                "state": "UNKNOWN",
                "cwe": [],
                "references": [],
                "affected": [],
                "ssvc": {},
                "published": "",
                "assigner": "",
                "credits": [],
            }

            meta = json_data.get('cveMetadata', {}) or {}
            data['state'] = meta.get('state', 'UNKNOWN')
            data['assigner'] = str(meta.get('assignerShortName') or '').strip()
            data['published'] = str(meta.get('datePublished') or '')[:10]
            data['affected'] = self.parse_affected(cna.get('affected', []))

            descriptions = cna.get('descriptions', []) or []
            en_desc = next((d.get('value') for d in descriptions
                            if (d.get('lang') or '').lower().startswith('en') and d.get('value')), None)
            if en_desc:
                data['description'] = en_desc
            elif descriptions and descriptions[0].get('value'):
                data['description'] = descriptions[0]['value']

            title = (cna.get('title') or '').strip()
            if not title:
                aff0 = next((a for a in data['affected']
                             if a.get('product') and a['product'].lower() not in ('n/a', 'unknown')), None)
                if aff0:
                    vendor = (aff0.get('vendor') or '').strip()
                    product = aff0['product'].strip()
                    use_vendor = vendor and vendor.lower() not in ('n/a', 'unknown') \
                        and vendor.split()[0].lower() not in product.lower()
                    title = f"{vendor} {product} vulnerability" if use_vendor else f"{product} vulnerability"
                elif data['description'] != 'N/A':
                    title = data['description'].split('. ')[0][:110]
            data['title'] = title or 'N/A'
            
            data['cvss_scores'] = collect_cvss([cna])
            data['cvss'], data['cvss_vector'], data['cvss_version'] = \
                pick_cvss(data['cvss_scores'])
            
            for pt in cna.get('problemTypes', []):
                for desc in pt.get('descriptions', []):
                    for field in (desc.get('cweId', ''), desc.get('description', '')):
                        for m in re.findall(r'CWE-\d{1,4}\b', str(field)):
                            if m not in data['cwe']:
                                data['cwe'].append(m)
            
            for ref in cna.get('references', []):
                if 'url' in ref:
                    data['references'].append(ref['url'])

            for credit in cna.get('credits', []) or []:
                value = str((credit or {}).get('value') or '').strip()
                if value:
                    data['credits'].append(value)

            self._enrich_from_adp(json_data, data)

            logger.debug(f"Enriched {cve_id}: CVSS={data['cvss']}, State={data['state']}, SSVC={data['ssvc'].get('exploitation','-')}")
            return data

        except Exception as e:
            logger.error(f"{cve_id} 파싱 실패: {e}")
            return self._error_response(cve_id)
    
    def _enrich_from_adp(self, json_data: Dict, data: Dict) -> None:
        try:
            adp_containers = json_data.get('containers', {}).get('adp', []) or []
        except AttributeError:
            return

        for container in adp_containers:
            provider = (container.get('providerMetadata') or {}).get('shortName', '')
            if provider != 'CISA-ADP':
                continue

            for metric in container.get('metrics', []) or []:
                other = metric.get('other') or {}
                if other.get('type') == 'ssvc':
                    for opt in (other.get('content', {}) or {}).get('options', []) or []:
                        for key, val in opt.items():
                            data['ssvc'][key.lower().replace(' ', '_')] = val

            # ADP(CISA vulnrichment 등)가 준 점수도 합친다. CNA 가 4.0 만 냈는데
            # ADP 가 3.1 을 붙이는 경우가 흔하다 — 그걸 버리면 화면이 남들과 어긋난다.
            before = data['cvss']
            extra = collect_cvss([container])
            for label, val in extra.items():
                data.setdefault('cvss_scores', {}).setdefault(label, val)
            if data.get('cvss_scores'):
                data['cvss'], data['cvss_vector'], data['cvss_version'] = \
                    pick_cvss(data['cvss_scores'])
            if before == 0.0 and data['cvss'] > 0:
                logger.info(f"  ADP CVSS 보강: {data['id']} → {data['cvss']} "
                            f"(v{data.get('cvss_version') or '?'})")

            if not data['cwe']:
                for pt in container.get('problemTypes', []) or []:
                    for desc in pt.get('descriptions', []) or []:
                        cwe_id = desc.get('cweId', '')
                        if cwe_id:
                            data['cwe'].append(cwe_id)


    def fetch_vulncheck_kev(self) -> bool:
        data = enrichment_sources.load_vulncheck_kev()
        if data is None:
            return False
        self.vulncheck_kev_set = set(data)
        logger.info(f"VulnCheck KEV {len(self.vulncheck_kev_set)}건 적재")
        return True

    def enrich_from_nvd(self, cve_data: Dict) -> Dict:
        api_key = os.environ.get("NVD_API_KEY")
        cve_id = cve_data['id']
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
            
            if cve_data['cvss'] == 0.0:
                for key in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30']:
                    metric_list = metrics.get(key, [])
                    if metric_list:
                        cvss_data = metric_list[0].get('cvssData', {})
                        cve_data['cvss'] = cvss_data.get('baseScore', 0.0)
                        cve_data['cvss_vector'] = cvss_data.get('vectorString', 'N/A')
                        logger.info(f"  NVD CVSS 보충: {cve_id} → {cve_data['cvss']}")
                        break
            
            if not cve_data['cwe']:
                for weakness in cve_item.get('weaknesses', []):
                    for desc in weakness.get('description', []):
                        cwe_val = desc.get('value', '')
                        if cwe_val and cwe_val != 'NVD-CWE-noinfo':
                            cve_data['cwe'].append(cwe_val)
            
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
        result = self._check_nomi_sec(cve_id)
        if result['has_poc']:
            return result

        result = self._check_trickest(cve_id)
        return result

    def _check_nomi_sec(self, cve_id: str) -> Dict:
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
        try:
            parts = cve_id.split('-')
            year = parts[1]

            url = f"https://raw.githubusercontent.com/trickest/cve/main/{year}/{cve_id}.md"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                content = response.text
                poc_urls = re.findall(r'https://github\.com/[^\s\)]+', content)
                poc_urls = list(dict.fromkeys(poc_urls))[:3]

                logger.info(f"  🔥 PoC 발견 (trickest): {cve_id} ({len(poc_urls)}개)")
                return {"has_poc": True, "poc_count": len(poc_urls) or 1, "poc_urls": poc_urls}

            return {"has_poc": False, "poc_count": 0, "poc_urls": []}

        except Exception as e:
            logger.debug(f"trickest PoC 확인 실패 ({cve_id}): {e}")
            return {"has_poc": False, "poc_count": 0, "poc_urls": []}
    
    def check_github_advisory(self, cve_id: str) -> Dict:
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
        if not cve_data.get('_nvd_enriched'):
            cve_data = self.enrich_from_nvd(cve_data)
        return self._augment_affected_from_cpe(cve_data)

    def _augment_affected_from_cpe(self, cve_data: Dict) -> Dict:
        cpes = cve_data.get('nvd_cpe') or []
        if not cpes:
            return cve_data
        existing = cve_data.get('affected') or []
        has_valid_vendor = any(
            str(a.get('vendor') or '').lower() not in ('', 'unknown', 'n/a') for a in existing
        )
        if has_valid_vendor:
            return cve_data
        derived = affected_from_cpes(cpes, existing)
        if derived:
            cve_data['affected'] = derived
            logger.info(f"  📦 NVD CPE로 영향자산 보강: {cve_data['id']} ({len(derived)}건)")
        return cve_data

    def enrich_cheap_signals(self, cve_data: Dict) -> Dict:
        cve_id = cve_data['id']
        cve_data['is_vulncheck_kev'] = cve_id in self.vulncheck_kev_set
        cve_data['is_kev_ransomware'] = cve_id in self.kev_ransomware
        edb_entry = enrichment_sources.exploitdb_entry(cve_id)
        cve_data['has_public_exploit'] = edb_entry is not None
        if edb_entry and edb_entry[1]:
            cve_data['_exploit_db_url'] = f"https://www.exploit-db.com/exploits/{edb_entry[1]}"
        msf_modules = enrichment_sources.metasploit_modules(cve_id)
        cve_data['has_metasploit_module'] = bool(msf_modules)
        cve_data['metasploit_modules'] = [m['fullname'] for m in msf_modules[:3]]
        if msf_modules:
            logger.info(f"  🧨 Metasploit 모듈: {cve_id} ({len(msf_modules)}개, 최고 rank={msf_modules[0]['rank_name']})")
        tpl = enrichment_sources.nuclei_template(cve_id)
        cve_data['has_nuclei_template'] = tpl is not None
        if tpl:
            cve_data['nuclei_severity'] = tpl.get('severity', '')
            cve_data['_nuclei_url'] = enrichment_sources.nuclei_template_url(tpl.get('path', ''))
            logger.info(f"  🎯 nuclei 템플릿: {cve_id} ({tpl.get('severity', '?')})")
        prov = ai_provenance.detect(cve_id, cve_data.get('credits'), self.ai_ledger)
        if prov:
            cve_data.update(prov.as_state())
            logger.info(f"  🤖 AI 발견: {cve_id} ({prov.program}) — {prov.detail[:80]}")
        else:
            cve_data['ai_discovered'] = False
        self.fill_product_from_kev(cve_data)
        return cve_data

    def fill_product_from_kev(self, cve_data: Dict) -> Dict:
        # 옛날 CVE 레코드에는 affected 블록이 없어 vendor/product 가 'n/a' 로 남는다.
        # 무작위 60건 실측으로 KEV 의 42%가 그랬다 — 그런데 그게 지금 악용 중인 것들이라,
        # 화면에서 제품 이름으로 찾을 수 없다는 뜻이었다(제목에만 적혀 있다).
        # CISA 가 KEV 에 붙여 둔 vendorProject/product 는 사람이 정리한 값이라 깨끗하다.
        # 레코드가 제대로 채워져 있으면 손대지 않는다 — 그쪽이 더 상세하다.
        vendor, product = self.kev_product.get(cve_data.get('id'), ('', ''))
        if not product:
            return cve_data
        affected = cve_data.get('affected') or []
        if any(_meaningful(a.get('product')) for a in affected if isinstance(a, dict)):
            return cve_data
        cve_data['affected'] = [{
            "vendor": vendor or "Unknown",
            "product": product,
            "versions": affected[0].get('versions') if affected else "정보 없음",
            "patch_version": affected[0].get('patch_version') if affected else None,
            "source": "CISA KEV",
        }]
        return cve_data

    def enrich_threat_intel(self, cve_data: Dict) -> Dict:
        cve_id = cve_data['id']
        logger.info(f"위협 인텔리전스 수집(고위험): {cve_id}")

        if 'has_public_exploit' not in cve_data:
            self.enrich_cheap_signals(cve_data)

        cve_data = self.fill_affected_from_nvd(cve_data)

        poc_info = self.check_poc_exists(cve_id)
        cve_data['has_poc'] = poc_info['has_poc']
        cve_data['poc_count'] = poc_info['poc_count']
        cve_data['poc_urls'] = poc_info['poc_urls']

        cve_data['github_advisory'] = self.check_github_advisory(cve_id)

        return cve_data
    
    def _error_response(self, cve_id: str, state: str = "ERROR") -> Dict:
        return {
            "id": cve_id,
            "title": "Error",
            "cvss": 0.0,
            "cvss_vector": "N/A",
            "cvss_version": "",
            "cvss_scores": {},
            "description": "Error",
            "state": state,
            "cwe": [],
            "references": [],
            "affected": []
        }
