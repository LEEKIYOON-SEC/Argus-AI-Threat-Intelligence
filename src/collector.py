import os
import re
from typing import Dict, List, Optional, Set, Tuple

import ai_provenance
import enrichment_sources
from logger import logger


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


def _clip(text: str, limit: int) -> str:
    """단어 중간에서 자르지 않는다.

    CNA 가 title 을 안 주면 설명 첫 문장을 제목으로 쓰는데, 그냥 [:110] 이면
    'CVE-2016-0193' 처럼 '…or cause a de' 로 끊긴다. 그 문자열이 그대로 화면 제목이 되고
    번역 입력으로도 들어간다.
    """
    text = (text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(" ,;:-")
    return (cut or text[:limit]) + "…"


_SSVC_FLAT = ("exploitation", "automatable", "technical_impact")


def flatten_ssvc(data: Dict) -> Dict:
    """중첩된 ssvc 를 risk.evaluate 가 읽는 평탄한 키로 옮긴다.

    CISA vulnrichment 의 SSVC 는 ADP 컨테이너에서 `data['ssvc']['exploitation']` 처럼
    중첩으로 들어온다. 그런데 risk.evaluate 는 `state['ssvc_exploitation']` 평탄한 키만
    읽는다. 이 한 줄이 없어서 **트리거 3개가 통째로 죽어 있었다** —

        ssvc_active        T0  악용 진행형        실측 439건이 발화했어야 했다
        ssvc_automatable   T2  자동화 대량공격    실측 1,647건
        ssvc_total_impact  T2  완전 장악          실측 3,699건

    export 와 database._waf_minimal_copy 는 중첩본을 폴백으로 읽고 있어서 화면에는
    보였다. 판정만 못 봤다 — 화면에 'SSVC: active' 가 뜨는데 등급은 T3 인 상태였다.
    """
    ssvc = data.get("ssvc")
    if not isinstance(ssvc, dict):
        return data
    for key in _SSVC_FLAT:
        value = ssvc.get(key)
        if isinstance(value, str) and value.strip():
            data[f"ssvc_{key}"] = value.strip().lower()
    return data


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
                    title = _clip(data['description'].split('. ')[0], 110)
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
            flatten_ssvc(data)

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
