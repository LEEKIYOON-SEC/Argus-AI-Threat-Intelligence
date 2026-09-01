import datetime
import json
import os
import threading
from typing import Dict, List, Optional, Tuple

import pytz
import requests

import risk
from analyzer import Analyzer
from logger import logger
from notifier import SlackNotifier
from rule_manager import RuleManager

KST = pytz.timezone('Asia/Seoul')

CVSS_MAP = {
    "AV:N": "공격 경로: 네트워크 (Network)", "AV:A": "공격 경로: 인접 (Adjacent)", "AV:L": "공격 경로: 로컬 (Local)", "AV:P": "공격 경로: 물리적 (Physical)",
    "AC:L": "복잡성: 낮음", "AC:H": "복잡성: 높음",
    "PR:N": "필요 권한: 없음", "PR:L": "필요 권한: 낮음", "PR:H": "필요 권한: 높음",
    "UI:N": "사용자 관여: 없음", "UI:R": "사용자 관여: 필수",
    "S:U": "범위: 변경 없음", "S:C": "범위: 변경됨 (Changed)",
    "C:H": "기밀성: 높음", "C:L": "기밀성: 낮음", "C:N": "기밀성: 없음",
    "I:H": "무결성: 높음", "I:L": "무결성: 낮음", "I:N": "무결성: 없음",
    "A:H": "가용성: 높음", "A:L": "가용성: 낮음", "A:N": "가용성: 없음",

    "E:X": "악용 가능성: 미정의", "E:U": "악용 가능성: 입증 안됨", "E:P": "악용 가능성: 개념 증명(PoC)", "E:F": "악용 가능성: 기능적", "E:H": "악용 가능성: 높음",
    "RL:X": "대응 수준: 미정의", "RL:O": "대응 수준: 공식 패치", "RL:T": "대응 수준: 임시 수정", "RL:W": "대응 수준: 우회 가능", "RL:U": "대응 수준: 사용 불가",
    "RC:X": "보고 신뢰도: 미정의", "RC:U": "보고 신뢰도: 미확인", "RC:R": "보고 신뢰도: 합리적", "RC:C": "보고 신뢰도: 확인됨",

    "MAV:N": "수정된 경로: 네트워크", "MAV:A": "수정된 경로: 인접", "MAV:L": "수정된 경로: 로컬", "MAV:P": "수정된 경로: 물리적",
    "MAC:L": "수정된 복잡성: 낮음", "MAC:H": "수정된 복잡성: 높음",
    "MPR:N": "수정된 권한: 없음", "MPR:L": "수정된 권한: 낮음", "MPR:H": "수정된 권한: 높음",
    "MUI:N": "수정된 관여: 없음", "MUI:R": "수정된 관여: 필수",
    "MS:U": "수정된 범위: 변경 없음", "MS:C": "수정된 범위: 변경됨",
    "MC:H": "수정된 기밀성: 높음", "MC:L": "수정된 기밀성: 낮음", "MC:N": "수정된 기밀성: 없음",
    "MI:H": "수정된 무결성: 높음", "MI:L": "수정된 무결성: 낮음", "MI:N": "수정된 무결성: 없음",
    "MA:H": "수정된 가용성: 높음", "MA:L": "수정된 가용성: 낮음", "MA:N": "수정된 가용성: 없음",
    "CR:X": "기밀성 요구: 미정의", "CR:L": "기밀성 요구: 낮음", "CR:M": "기밀성 요구: 보통", "CR:H": "기밀성 요구: 높음",
    "IR:X": "무결성 요구: 미정의", "IR:L": "무결성 요구: 낮음", "IR:M": "무결성 요구: 보통", "IR:H": "무결성 요구: 높음",
    "AR:X": "가용성 요구: 미정의", "AR:L": "가용성 요구: 낮음", "AR:M": "가용성 요구: 보통", "AR:H": "가용성 요구: 높음",

    "AT:N": "공격 기술: 없음", "AT:P": "공격 기술: 존재(Present)",
    "VC:H": "취약시스템 기밀성: 높음", "VC:L": "취약시스템 기밀성: 낮음", "VC:N": "취약시스템 기밀성: 없음",
    "VI:H": "취약시스템 무결성: 높음", "VI:L": "취약시스템 무결성: 낮음", "VI:N": "취약시스템 무결성: 없음",
    "VA:H": "취약시스템 가용성: 높음", "VA:L": "취약시스템 가용성: 낮음", "VA:N": "취약시스템 가용성: 없음",
    "SC:H": "후속시스템 기밀성: 높음", "SC:L": "후속시스템 기밀성: 낮음", "SC:N": "후속시스템 기밀성: 없음",
    "SI:H": "후속시스템 무결성: 높음", "SI:L": "후속시스템 무결성: 낮음", "SI:N": "후속시스템 무결성: 없음",
    "SA:H": "후속시스템 가용성: 높음", "SA:L": "후속시스템 가용성: 낮음", "SA:N": "후속시스템 가용성: 없음",

    "MAT:N": "수정된 공격 기술: 없음", "MAT:P": "수정된 공격 기술: 존재",
    "MVC:H": "수정된 취약시스템 기밀성: 높음", "MVC:L": "수정된 취약시스템 기밀성: 낮음", "MVC:N": "수정된 취약시스템 기밀성: 없음",
    "MVI:H": "수정된 취약시스템 무결성: 높음", "MVI:L": "수정된 취약시스템 무결성: 낮음", "MVI:N": "수정된 취약시스템 무결성: 없음",
    "MVA:H": "수정된 취약시스템 가용성: 높음", "MVA:L": "수정된 취약시스템 가용성: 낮음", "MVA:N": "수정된 취약시스템 가용성: 없음",
    "MSC:H": "수정된 후속시스템 기밀성: 높음", "MSC:L": "수정된 후속시스템 기밀성: 낮음", "MSC:N": "수정된 후속시스템 기밀성: 없음", "MSC:S": "수정된 후속시스템 기밀성: 안전(Safety)",
    "MSI:H": "수정된 후속시스템 무결성: 높음", "MSI:L": "수정된 후속시스템 무결성: 낮음", "MSI:N": "수정된 후속시스템 무결성: 없음", "MSI:S": "수정된 후속시스템 무결성: 안전(Safety)",
    "MSA:H": "수정된 후속시스템 가용성: 높음", "MSA:L": "수정된 후속시스템 가용성: 낮음", "MSA:N": "수정된 후속시스템 가용성: 없음", "MSA:S": "수정된 후속시스템 가용성: 안전(Safety)",

    "S:X": "안전(Safety): 미정의", "S:N": "안전(Safety): 무시 가능", "S:P": "안전(Safety): 존재(Present)",
    "AU:X": "자동화 가능성: 미정의", "AU:N": "자동화 가능성: 아니오", "AU:Y": "자동화 가능성: 예",
    "R:X": "복구(Recovery): 미정의", "R:A": "복구: 자동", "R:U": "복구: 사용자", "R:I": "복구: 복구 불가",
    "V:X": "가치 밀도: 미정의", "V:D": "가치 밀도: 분산(Diffuse)", "V:C": "가치 밀도: 집중(Concentrated)",
    "RE:X": "대응 노력: 미정의", "RE:L": "대응 노력: 낮음", "RE:M": "대응 노력: 보통", "RE:H": "대응 노력: 높음",
    "U:X": "긴급성: 미정의", "U:Clear": "긴급성: 명확함", "U:Green": "긴급성: 낮음(Green)", "U:Amber": "긴급성: 주의(Amber)", "U:Red": "긴급성: 높음(Red)"
}


def parse_cvss_vector(vector_str: str) -> str:
    if not vector_str or vector_str == "N/A":
        return "정보 없음"
    
    parts = vector_str.split('/')
    mapped_parts = []
    
    for part in parts:
        if ':' in part:
            full_key = part
            desc = CVSS_MAP.get(full_key, f"**{part}**")
            if full_key in CVSS_MAP:
                mapped_parts.append(f"• {desc}")
            else:
                mapped_parts.append(f"• {part}")
    
    return "<br>".join(mapped_parts)


_PKG_INDEX: Optional[Dict] = None
_PKG_INDEX_LOCK = threading.Lock()


def _package_index() -> Dict:
    global _PKG_INDEX
    if _PKG_INDEX is not None:
        return _PKG_INDEX
    with _PKG_INDEX_LOCK:
        if _PKG_INDEX is None:
            _PKG_INDEX = _load_package_index()
    return _PKG_INDEX


def _load_package_index() -> Dict:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        url = f"https://{owner.lower()}.github.io/{name}/data/cve-packages.json"
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "argus-report"})
            with urllib.request.urlopen(req, timeout=180) as r:
                idx = (json.loads(r.read().decode("utf-8")) or {}).get("packages") or {}
            logger.info(f"패키지 사전 로드(배포본): {len(idx):,}건")
            return idx
        except Exception as e:
            logger.warning(f"패키지 사전 배포본 로드 실패({e}) → 체크아웃 사본 확인")

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "docs", "data", "cve-packages.json")
    try:
        with open(path, encoding="utf-8") as f:
            idx = (json.load(f) or {}).get("packages") or {}
        logger.info(f"패키지 사전 로드(파일): {len(idx):,}건")
        return idx
    except (OSError, ValueError):
        return {}


_FIXED_ROW_CAP = 20


def _fixed_version_lines(cve_id: str) -> str:
    pkgs = _package_index().get(cve_id) or {}
    lines = []
    for pkg, eco_map in sorted(pkgs.items()):
        for eco, fixes in sorted((eco_map or {}).items()):
            good = [f for f in (fixes or []) if f]
            if good:
                lines.append(f"| `{pkg}` | {eco} | **{', '.join(good)}** |")
    if not lines:
        return ""
    shown, omitted = lines[:_FIXED_ROW_CAP], max(0, len(lines) - _FIXED_ROW_CAP)
    note = (f"\n\n<sub>⚠️ 항목이 많아 {omitted}행을 생략했습니다 — 전체는 "
            f"[OSV.dev](https://osv.dev/vulnerability/{cve_id})에서 확인하세요.</sub>"
            if omitted else "")
    return ("\n## 📦 패치 버전 (OSV)\n"
            "| 패키지 | 배포판·생태계 | 이 버전 이상으로 |\n| :--- | :--- | :--- |\n"
            + "\n".join(shown) + note
            + "\n\n<sub>출처: [OSV.dev](https://osv.dev) (CC-BY 4.0) — 설치된 배포판·릴리스에 "
              "맞는 행을 보세요. Linux 커널은 배포판 기본 패키지(`linux`)만 싣습니다 — "
              "클라우드·OEM 변종(linux-aws·linux-azure·linux-oem 등)을 쓰신다면 버전 체계가 "
              f"달라 [OSV.dev](https://osv.dev/vulnerability/{cve_id})에서 해당 변종을 "
              "확인하세요. 실제 적용 전 벤더 권고를 확인하시기 바랍니다.</sub>\n")


def _rule_license_note(rule_info: Dict) -> str:
    bits = []
    lic = rule_info.get('license')
    if lic:
        bits.append(f"**License:** {lic}")
    author = rule_info.get('author')
    if author:
        bits.append(f"**Author:** {author}")
    lic_url = rule_info.get('license_url')
    if lic_url and lic_url != "N/A":
        bits.append(f"[라이선스 원문]({lic_url})")
    url = rule_info.get('url')
    if url:
        bits.append(f"[출처]({url})")
    note = rule_info.get('note')
    if note:
        bits.append(note)
    if not bits:
        return ""
    return "\n> " + " · ".join(bits) + "\n"

def _priority_banner(cve_data: Dict) -> str:
    verdict = risk.evaluate(cve_data)
    labels = verdict.labels()
    if verdict.tier == risk.T0:
        level = "🔴 즉시 대응"
    elif verdict.tier == risk.T1:
        level = "🟠 높음"
    elif verdict.tier == risk.T2:
        level = "🟡 관찰"
    else:
        level = "⚪ 정보"
    why = " · ".join(labels[:3]) if labels else "판정 신호 없음"
    return f"> **⚡ 대응 우선순위: {level}** — {why}"


def _epss_caption(cve_data: Dict) -> str:
    epss = cve_data.get('epss', 0.0) or 0.0
    surge = " · **⚠️ 급증**" if epss >= 0.1 else ""
    return f"<sub>EPSS {epss*100:.2f}% — 향후 30일 내 실제 악용 시도 확률 (출처: FIRST.org){surge}</sub>"

def _display_title(cve_data: dict) -> str:
    # 알림 시점(fast-lane/스냅샷 대조)의 상태에는 title_ko 가 없다 — 번역은 bulk-lane 이
    # 나중에 채운다. 예전에는 cve_data['title_ko'] 로 바로 꺼내 KeyError 가 났고,
    # create_github_issue 의 except 가 "GitHub Issue 생성 실패: 'title_ko'" 한 줄로
    # 삼켰다. 그래서 알림에 리포트 링크가 없이 나가고, 다음 시간의 리포트 보강이
    # (거기서만 setdefault 로 메우고 있어서) 뒤늦게 만들어 주고 있었다.
    return (str(cve_data.get('title_ko') or '').strip()
            or str(cve_data.get('title') or '').strip()
            or cve_data.get('id', 'CVE'))


def _issue_labels(cve_data: Dict) -> List[str]:
    verdict = risk.evaluate(cve_data)
    labels = ["security", "cve", f"tier:{verdict.tier.lower()}"]
    score = cve_data.get('cvss', 0.0) or 0.0
    labels.append("severity:critical" if score >= 9.0
                  else "severity:high" if score >= 7.0
                  else "severity:medium" if score >= 4.0 else "severity:low")
    if "kev" in verdict.triggers or "vulncheck_kev" in verdict.triggers:
        labels.append("kev")
    if verdict.triggers & {"metasploit", "ssvc_active", "nuclei"}:
        labels.append("exploited")
    if verdict.triggers & {"exploitdb", "poc"}:
        labels.append("poc")
    return labels


def create_github_issue(cve_data: Dict, reason: str) -> Tuple[Optional[str], Optional[Dict]]:
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    
    if not repo:
        logger.warning("GITHUB_REPOSITORY 미설정, Issue 생성 건너뜀")
        return None, None
    
    try:
        logger.info(f"AI 분석 시작: {cve_data['id']}")
        analyzer = Analyzer()
        analysis = analyzer.analyze_cve(cve_data)

        rule_manager = RuleManager()
        rules = rule_manager.search_public_only(cve_data['id'])

        has_official = bool(
            rules.get('network')
            or any(rules.get(k) for k in ('sigma', 'nuclei', 'splunk', 'yara'))
        )
        
        body = _build_issue_body(cve_data, reason, analysis, rules)
        
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "title": f"[Argus] {cve_data['id']}: {_display_title(cve_data)}",
            "body": body,
            "labels": _issue_labels(cve_data)
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        
        issue_url = response.json().get("html_url")
        logger.info(f"GitHub Issue 생성 성공: {issue_url}")
        
        return issue_url, {"has_official": has_official, "rules": rules}
        
    except Exception as e:
        logger.error(f"GitHub Issue 생성 실패: {e}")
        return None, None

def _build_issue_body(cve_data: Dict, reason: str, analysis: Dict, rules: Dict) -> str:
    analysis = analysis or {}
    rules = rules or {}
    score = cve_data.get('cvss') or 0
    if score >= 9.0: color = "FF0000"
    elif score >= 7.0: color = "FD7E14"
    elif score >= 4.0: color = "FFC107"
    elif score > 0: color = "28A745"
    else: color = "CCCCCC"
    
    kev_color = "FF0000" if cve_data.get('is_kev') else "CCCCCC"

    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{(cve_data.get('epss') or 0)*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data.get('is_kev') else 'No'}-{kev_color})"

    if cve_data.get('ssvc_exploitation') == 'active':
        badges += " ![SSVC](https://img.shields.io/badge/SSVC-Active-red)"
    if cve_data.get('has_metasploit_module'):
        badges += " ![Metasploit](https://img.shields.io/badge/Metasploit-Weaponized-8B0000)"
    if cve_data.get('has_public_exploit'):
        badges += " ![ExploitDB](https://img.shields.io/badge/ExploitDB-Public-orange)"
    if cve_data.get('has_nuclei_template'):
        badges += " ![nuclei](https://img.shields.io/badge/nuclei-Template-9146FF)"
    if cve_data.get('is_vulncheck_kev'):
        badges += " ![VulnCheck KEV](https://img.shields.io/badge/VulnCheck_KEV-Listed-B00020)"
    if cve_data.get('ai_discovered'):
        badges += " ![AI Discovered](https://img.shields.io/badge/AI_Discovered-D97706)"

    signal_lines = []
    if cve_data.get('is_kev'):
        due = cve_data.get('kev_due_date')
        ransom = " · **랜섬웨어 캠페인 사용 확인**" if cve_data.get('is_kev_ransomware') else ""
        due_str = f" · CISA 조치 기한 {due}" if due else ""
        signal_lines.append(f"- **CISA KEV 등재** (U.S. Government Work): 실제 악용 확인{ransom}{due_str}")
    if cve_data.get('is_vulncheck_kev'):
        signal_lines.append("- **VulnCheck KEV 등재**: 악용 근거 확보 "
                            "(This product uses VulnCheck KEV — 출처: VulnCheck)")
    if cve_data.get('has_nuclei_template'):
        url = cve_data.get('_nuclei_url')
        link = f" — [템플릿]({url})" if url else ""
        sev = cve_data.get('nuclei_severity') or ''
        signal_lines.append(
            f"- **nuclei 템플릿 공개** (nuclei-templates, ProjectDiscovery, MIT): "
            f"대량 스캔·검증 가능{f' · severity={sev}' if sev else ''}{link}")
    if cve_data.get('ai_discovered'):
        prog = cve_data.get('ai_program') or 'AI'
        detail = cve_data.get('ai_detail') or ''
        ai_url = cve_data.get('ai_url')
        ai_link = f" — [공개 레저]({ai_url})" if ai_url else ""
        signal_lines.append(
            f"- **AI 발견 취약점** ({prog}): {detail}{ai_link}\n"
            f"  <sub>AI가 찾아 책임공개된 건입니다. 공개 시점에 패치가 이미 나와 있는 경우가"
            f" 많지만, 공개와 동시에 상세가 함께 공개되므로 N-day 위험은 실재합니다.</sub>")
    ssvc = cve_data.get('ssvc') or {}
    if ssvc:
        parts = [f"{k}={v}" for k, v in ssvc.items()]
        signal_lines.append(f"- **CISA SSVC** (vulnrichment, CC0): {', '.join(parts)}")
    if cve_data.get('has_metasploit_module'):
        mods = cve_data.get('metasploit_modules', [])
        mod_str = ", ".join(f"`{m}`" for m in mods) if mods else "존재"
        signal_lines.append(f"- **Metasploit 모듈** (Metasploit Framework, Rapid7, BSD-3-Clause): {mod_str}")
    if cve_data.get('has_public_exploit'):
        edb_url = cve_data.get('_exploit_db_url')
        link = f" — [Exploit-DB]({edb_url})" if edb_url else ""
        signal_lines.append(f"- **공개 익스플로잇**: ExploitDB 등재{link}")
    if cve_data.get('has_poc'):
        poc_urls = cve_data.get('poc_urls', [])
        poc_link = f" — [PoC 링크]({poc_urls[0]})" if poc_urls else ""
        signal_lines.append(
            f"- **PoC 공개** (출처: nomi-sec/trickest, 원문 미게시·링크만): "
            f"{cve_data.get('poc_count', len(poc_urls))}건{poc_link}")
    threat_signals = ("## 🧨 위협 신호\n" + "\n".join(signal_lines) + "\n") if signal_lines else ""

    cwe_str = ", ".join(cve_data.get('cwe') or []) or "N/A"
    
    affected_rows = ""
    for item in cve_data.get('affected') or []:
        affected_rows += (f"| {item.get('vendor') or '-'} | {item.get('product') or '-'} "
                          f"| {item.get('versions') or '-'} |\n")
    if not affected_rows:
        affected_rows = "| - | - | - |"

    fixed_block = _fixed_version_lines(cve_data['id'])

    mitigation_list = "\n".join([f"- {m}" for m in analysis.get('mitigation', [])])
    
    notes = {}
    if cve_data.get('_exploit_db_url'):
        notes[cve_data['_exploit_db_url']] = " (Exploit-DB PoC)"
    for u in cve_data.get('poc_urls', [])[:3]:
        notes.setdefault(u, " (PoC, nomi-sec/trickest)")
    ref_items = []
    seen = set()
    for r in cve_data.get('references') or []:
        if r and r not in seen:
            ref_items.append(f"{r}{notes.get(r, '')}")
            seen.add(r)
    for u, note in notes.items():
        if u not in seen:
            ref_items.append(f"{u}{note}")
            seen.add(u)
    ref_list = "\n".join([f"- {r}" for r in ref_items]) if ref_items else "- 등록된 참고 링크 없음"

    vector_details = parse_cvss_vector(cve_data.get('cvss_vector', 'N/A'))
    
    _RULE_KINDS = (
        ("sigma", "Sigma Rule", "yaml"),
        ("nuclei", "nuclei Template", "yaml"),
        ("splunk", "Splunk 탐지 (ESCU)", "yaml"),
        ("yara", "YARA Rule", "yara"),
    )
    has_any_rules = bool(rules.get('network')) or any(rules.get(k) for k, _, _ in _RULE_KINDS)
    if has_any_rules:
        sources = sorted({r['source'] for r in (rules.get('network') or []) if r.get('source')}
                         | {rules[k]['source'] for k, _, _ in _RULE_KINDS
                            if rules.get(k) and rules[k].get('source')})
        rules_section = ("## 🔎 공개 탐지 룰\n\n"
                         f"> 공개 룰셋({' / '.join(sources)})에서 확인된 룰입니다. "
                         "보안 장비 적용 전 자사 환경에 맞게 검토하세요.\n"
                         "> 각 룰의 출처·author·라이선스 고지를 함께 싣습니다.\n\n")
        for key, title, fence in _RULE_KINDS:
            info = rules.get(key)
            if not info or not info.get('code'):
                continue
            extra = ""
            if key == "nuclei" and info.get('severity'):
                extra = f" · severity={info['severity']}"
            rules_section += (f"### {title} ({info['source']}){extra}\n"
                              f"{_rule_license_note(info)}```{fence}\n{info['code']}\n```\n\n")
        for idx, net_rule in enumerate(rules.get('network') or [], 1):
            engine_name = net_rule.get('engine', 'unknown').upper()
            rules_section += (f"### Network Rule #{idx} ({net_rule['source']} - {engine_name})\n"
                              f"{_rule_license_note(net_rule)}```bash\n{net_rule['code']}\n```\n\n")
    else:
        rules_section = ""

    now_kst = datetime.datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S (KST)')

    priority = _priority_banner(cve_data)
    epss_caption = _epss_caption(cve_data)

    desc_ko = (cve_data.get('desc_ko') or '').strip()
    desc_en = (cve_data.get('description') or '').strip()
    overview_section = ""
    if desc_ko and desc_ko != 'N/A':
        overview_section = f"## 📄 취약점 개요\n{desc_ko}\n"
        if desc_en and desc_en != 'N/A' and desc_en != desc_ko:
            overview_section += f"\n<details><summary>원문 (English)</summary>\n\n> {desc_en}\n\n</details>\n"
        overview_section += "\n"
    elif desc_en and desc_en != 'N/A':
        overview_section = f"## 📄 취약점 개요\n{desc_en}\n\n"

    body = f"""# 🛡️ {_display_title(cve_data)}

> **탐지 일시:** {now_kst}
> **탐지 사유:** {reason}

{priority}

{badges}
{epss_caption}

**취약점 유형 (CWE):** {cwe_str}

{threat_signals}
{overview_section}## 📦 영향 받는 자산 (벤더 / 제품 / 버전)
| 벤더 | 제품 | 버전 |
| :--- | :--- | :--- |
{affected_rows}
{fixed_block}
## 🔍 AI 심층 분석
### 기술적 근본 원인
{analysis.get('root_cause', '-')}

### 🎯 공격 벡터 상세
| 항목 | 내용 |
| :--- | :--- |
| **공식 벡터** | `{cve_data.get('cvss_vector', 'N/A')}` |
| **상세 해석** | {vector_details} |

### 🏹 공격 시나리오 (MITRE ATT&CK)
{analysis.get('scenario', '정보 없음')}

### 💥 비즈니스 영향
{analysis.get('impact', '-')}

## 🛡️ 권고 대응 방안
{mitigation_list}

{rules_section}

## 🔗 참고 자료
{ref_list}

---
<sub>📊 **데이터 출처**: CVE(cvelistV5, CC0 1.0) · NVD(NIST, U.S. Government Work) ·
CISA KEV·SSVC/vulnrichment(U.S. Government Work / CC0 1.0) ·
EPSS([FIRST.org](https://www.first.org/epss/)) · [OSV.dev](https://osv.dev)(CC-BY 4.0) ·
GitHub Advisory · Metasploit Framework(Rapid7, BSD-3-Clause) ·
[nuclei-templates](https://github.com/projectdiscovery/nuclei-templates)(ProjectDiscovery, MIT) ·
This product uses VulnCheck KEV ·
[Anthropic Disclosure Ledger](https://red.anthropic.com/2026/cvd/ledger/)(AI 발견 취약점 출처) ·
PoC/ExploitDB(원문 미게시·링크만).
공개 탐지 룰은 각 출처·author·라이선스 고지를 보존합니다.
AI 분석·위험도 분류는 **참고용**이며 정확성을 보증하지 않습니다.</sub>
"""
    return body.strip()

def update_github_issue_with_official_rules(issue_url: str, cve_id: str, rules: Dict) -> bool:
    comment = f"""## ✅ 공개 탐지 룰 발견

{cve_id}에 대한 **공개 탐지 룰**이 새로 발견되었습니다. 아래 룰을 보안 장비에 참고 적용하세요.

"""
    kinds = (("sigma", "Sigma Rule", "yaml"), ("nuclei", "nuclei Template", "yaml"),
             ("splunk", "Splunk 탐지 (ESCU)", "yaml"), ("yara", "YARA Rule", "yara"))
    for key, title, fence in kinds:
        info = rules.get(key)
        if not info or not info.get('code'):
            continue
        comment += (f"### {title} ({info['source']})\n{_rule_license_note(info)}"
                    f"```{fence}\n{info['code']}\n```\n\n")
    for idx, net_rule in enumerate(rules.get('network') or [], 1):
        engine = net_rule.get('engine', 'unknown').upper()
        comment += (f"### Network Rule #{idx} ({net_rule['source']} - {engine})\n"
                    f"{_rule_license_note(net_rule)}```bash\n{net_rule['code']}\n```\n\n")

    notifier = SlackNotifier()
    return notifier.update_github_issue(issue_url, comment)

