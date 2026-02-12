import os
import datetime
import time
import requests
import textwrap
from google import genai
from google.genai import types
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
from analyzer import Analyzer
from rule_manager import RuleManager
import config

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# [수정] NVD CVSS v3.1 및 v4.0 표준 전체 매핑 (Environmental 포함)
CVSS_MAP = {
    # ==========================================
    # [CVSS 3.1 Base Metrics]
    # ==========================================
    "AV:N": "공격 경로: 네트워크 (Network)", "AV:A": "공격 경로: 인접 (Adjacent)", "AV:L": "공격 경로: 로컬 (Local)", "AV:P": "공격 경로: 물리적 (Physical)",
    "AC:L": "복잡성: 낮음", "AC:H": "복잡성: 높음",
    "PR:N": "필요 권한: 없음", "PR:L": "필요 권한: 낮음", "PR:H": "필요 권한: 높음",
    "UI:N": "사용자 관여: 없음", "UI:R": "사용자 관여: 필수",
    "S:U": "범위: 변경 없음", "S:C": "범위: 변경됨 (Changed)",
    "C:H": "기밀성: 높음", "C:L": "기밀성: 낮음", "C:N": "기밀성: 없음",
    "I:H": "무결성: 높음", "I:L": "무결성: 낮음", "I:N": "무결성: 없음",
    "A:H": "가용성: 높음", "A:L": "가용성: 낮음", "A:N": "가용성: 없음",

    # ==========================================
    # [CVSS 3.1 Temporal / Threat Metrics]
    # ==========================================
    "E:X": "악용 가능성: 미정의", "E:U": "악용 가능성: 입증 안됨", "E:P": "악용 가능성: 개념 증명(PoC)", "E:F": "악용 가능성: 기능적", "E:H": "악용 가능성: 높음",
    "RL:X": "대응 수준: 미정의", "RL:O": "대응 수준: 공식 패치", "RL:T": "대응 수준: 임시 수정", "RL:W": "대응 수준: 우회 가능", "RL:U": "대응 수준: 사용 불가",
    "RC:X": "보고 신뢰도: 미정의", "RC:U": "보고 신뢰도: 미확인", "RC:R": "보고 신뢰도: 합리적", "RC:C": "보고 신뢰도: 확인됨",

    # ==========================================
    # [CVSS 3.1 Environmental Metrics]
    # ==========================================
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

    # ==========================================
    # [CVSS 4.0 Base Metrics]
    # ==========================================
    "AT:N": "공격 기술: 없음", "AT:P": "공격 기술: 존재(Present)",
    "VC:H": "취약시스템 기밀성: 높음", "VC:L": "취약시스템 기밀성: 낮음", "VC:N": "취약시스템 기밀성: 없음",
    "VI:H": "취약시스템 무결성: 높음", "VI:L": "취약시스템 무결성: 낮음", "VI:N": "취약시스템 무결성: 없음",
    "VA:H": "취약시스템 가용성: 높음", "VA:L": "취약시스템 가용성: 낮음", "VA:N": "취약시스템 가용성: 없음",
    "SC:H": "후속시스템 기밀성: 높음", "SC:L": "후속시스템 기밀성: 낮음", "SC:N": "후속시스템 기밀성: 없음",
    "SI:H": "후속시스템 무결성: 높음", "SI:L": "후속시스템 무결성: 낮음", "SI:N": "후속시스템 무결성: 없음",
    "SA:H": "후속시스템 가용성: 높음", "SA:L": "후속시스템 가용성: 낮음", "SA:N": "후속시스템 가용성: 없음",

    # ==========================================
    # [CVSS 4.0 Environmental (Modified Base) Metrics] - 사용자 요청 반영
    # ==========================================
    # Modified Attack Requirements (MAT)
    "MAT:N": "수정된 공격 기술: 없음", "MAT:P": "수정된 공격 기술: 존재",
    
    # Modified Vuln System Impact (MVC, MVI, MVA)
    "MVC:H": "수정된 취약시스템 기밀성: 높음", "MVC:L": "수정된 취약시스템 기밀성: 낮음", "MVC:N": "수정된 취약시스템 기밀성: 없음",
    "MVI:H": "수정된 취약시스템 무결성: 높음", "MVI:L": "수정된 취약시스템 무결성: 낮음", "MVI:N": "수정된 취약시스템 무결성: 없음",
    "MVA:H": "수정된 취약시스템 가용성: 높음", "MVA:L": "수정된 취약시스템 가용성: 낮음", "MVA:N": "수정된 취약시스템 가용성: 없음",

    # Modified Subsequent System Impact (MSC, MSI, MSA)
    "MSC:H": "수정된 후속시스템 기밀성: 높음", "MSC:L": "수정된 후속시스템 기밀성: 낮음", "MSC:N": "수정된 후속시스템 기밀성: 없음", "MSC:S": "수정된 후속시스템 기밀성: 안전(Safety)",
    "MSI:H": "수정된 후속시스템 무결성: 높음", "MSI:L": "수정된 후속시스템 무결성: 낮음", "MSI:N": "수정된 후속시스템 무결성: 없음", "MSI:S": "수정된 후속시스템 무결성: 안전(Safety)",
    "MSA:H": "수정된 후속시스템 가용성: 높음", "MSA:L": "수정된 후속시스템 가용성: 낮음", "MSA:N": "수정된 후속시스템 가용성: 없음", "MSA:S": "수정된 후속시스템 가용성: 안전(Safety)",

    # ==========================================
    # [CVSS 4.0 Supplemental Metrics]
    # ==========================================
    "S:X": "안전(Safety): 미정의", "S:N": "안전(Safety): 무시 가능", "S:P": "안전(Safety): 존재(Present)",
    "AU:X": "자동화 가능성: 미정의", "AU:N": "자동화 가능성: 아니오", "AU:Y": "자동화 가능성: 예",
    "R:X": "복구(Recovery): 미정의", "R:A": "복구: 자동", "R:U": "복구: 사용자", "R:I": "복구: 복구 불가",
    "V:X": "가치 밀도: 미정의", "V:D": "가치 밀도: 분산(Diffuse)", "V:C": "가치 밀도: 집중(Concentrated)",
    "RE:X": "대응 노력: 미정의", "RE:L": "대응 노력: 낮음", "RE:M": "대응 노력: 보통", "RE:H": "대응 노력: 높음",
    "U:X": "긴급성: 미정의", "U:Clear": "긴급성: 명확함", "U:Green": "긴급성: 낮음(Green)", "U:Amber": "긴급성: 주의(Amber)", "U:Red": "긴급성: 높음(Red)"
}

def is_target_asset(cve_description, cve_id):
    desc_lower = cve_description.lower()
    for target in config.TARGET_ASSETS:
        vendor, product = target.get('vendor', '').lower(), target.get('product', '').lower()
        if vendor == "*" and product == "*": return True, "All Assets (*)"
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    return False, None

def generate_korean_summary(cve_data):
    prompt = f"""
    Task: Translate Title and Summarize Description into Korean.
    [Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
    [Format]
    제목: [Korean Title]
    내용: [Korean Summary (Max 3 lines)]
    Do NOT add intro/outro.
    """
    try:
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, contents=prompt,
            config=types.GenerateContentConfig(safety_settings=[types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE")])
        )
        text = response.text.strip()
        title_ko, desc_ko = cve_data['title'], cve_data['description'][:200]
        for line in text.split('\n'):
            if line.startswith("제목:"): title_ko = line.replace("제목:", "").strip()
            if line.startswith("내용:"): desc_ko = line.replace("내용:", "").strip()
        return title_ko, desc_ko
    except: return cve_data['title'], cve_data['description'][:200]

def parse_cvss_vector(vector_str):
    if not vector_str or vector_str == "N/A": return "정보 없음"
    parts = vector_str.split('/')
    mapped_parts = []
    
    for part in parts:
        if ':' in part:
            key, val = part.split(':')
            full_key = f"{key}:{val}"
            # 매핑 테이블에 전체 키(예: AV:N)가 있으면 그거 쓰고, 없으면 값만 영문으로 표시
            desc = CVSS_MAP.get(full_key, f"{key}:{val}")
            
            # 매핑된 텍스트가 있으면 그대로 사용
            if full_key in CVSS_MAP:
                mapped_parts.append(f"• {desc}")
            else:
                # 굵은 글씨 효과를 위해 키와 값 분리 (매핑 안 된 경우)
                mapped_parts.append(f"• **{key}**: {val}")
    
    return "<br>".join(mapped_parts)

def create_github_issue(cve_data, reason):
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo: return None

    # [Phase 1] Analyzer 호출
    print(f"[*] Analyzing {cve_data['id']} with Groq...")
    analyzer = Analyzer()
    analysis_result = analyzer.analyze_cve(cve_data)

    # [Phase 1] RuleManager 호출
    print(f"[*] Generating rules for {cve_data['id']}...")
    rule_manager = RuleManager()
    rules = rule_manager.get_rules(cve_data, analysis_result.get('rule_feasibility', False))

    # 데이터 준비
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    score = cve_data['cvss']
    color = "CCCCCC"
    if score >= 9.0: color = "FF0000"
    elif score >= 7.0: color = "FD7E14"
    elif score >= 4.0: color = "FFC107"
    elif score > 0: color = "28A745"
    kev_color = "FF0000" if cve_data['is_kev'] else "CCCCCC"
    
    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{cve_data['epss']*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data['is_kev'] else 'No'}-{kev_color})"

    affected_rows = ""
    for item in cve_data.get('affected', []):
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} |\n"
    if not affected_rows: affected_rows = "| - | - | - |"

    mitigation_list = "\n".join([f"- {m}" for m in analysis_result.get('mitigation', [])])
    ref_list = "\n".join([f"- {r}" for r in cve_data['references']])
    vector_details = parse_cvss_vector(cve_data.get('cvss_vector', 'N/A'))

    # 룰 섹션 구성
    rules_section = ""
    if rules['sigma'] or rules['snort'] or rules['yara']:
        rules_section = "## 🛡️ 탐지 룰 (Detection Rules)\n"
        if rules['sigma']:
            rules_section += f"### Sigma Rule ({rules['sigma']['source']})\n```yaml\n{rules['sigma']['code']}\n```\n"
        if rules['snort']:
            rules_section += f"### Snort Rule ({rules['snort']['source']})\n```bash\n{rules['snort']['code']}\n```\n"
        if rules['yara']:
            rules_section += f"### Yara Rule ({rules['yara']['source']})\n```yara\n{rules['yara']['code']}\n```\n"

    body = f"""# 🛡️ {cve_data['title_ko']}

> **탐지 일시:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}
> **탐지 사유:** {reason}

{badges}
**취약점 유형 (CWE):** {cwe_str}

## 📦 영향 받는 자산
| 벤더 (Vendor) | 제품 (Product) | 버전 (Versions) |
| :--- | :--- | :--- |
{affected_rows}

## 🔍 심층 분석 (Deep Analysis)
| 항목 | 내용 |
| :--- | :--- |
| **기술적 원인** | {analysis_result.get('root_cause', '-')} |
| **비즈니스 영향** | {analysis_result.get('impact', '-')} |

### 🏹 공격 시나리오
> {analysis_result.get('scenario', '정보 없음')}

### 🏹 공격 벡터 상세
| 항목 | 내용 |
| :--- | :--- |
| **공식 벡터** | `{cve_data.get('cvss_vector', 'N/A')}` |
| **상세 분석** | {vector_details} |

## 🛡️ 대응 방안
{mitigation_list}

{rules_section}

## 🔗 참고 자료
{ref_list}
"""
    body = body.strip()

    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    payload = {"title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}", "body": body, "labels": ["security", "cve"]}
    
    resp = requests.post(url, headers=headers, json=payload)
    if resp.status_code == 201: return resp.json().get("html_url")
    else: return None

def main():
    print(f"[*] Argus Phase 1 시작 (Model: {config.MODEL_PHASE_1})")
    collector, db, notifier = Collector(), ArgusDB(), SlackNotifier()
    collector.fetch_kev()
    target_cve_ids = collector.fetch_recent_cves(hours=2)
    if not target_cve_ids: return
    collector.fetch_epss(target_cve_ids)
    print(f"[*] 분석 대상: {len(target_cve_ids)}건")

    for cve_id in target_cve_ids:
        try:
            time.sleep(20)
            raw_data = collector.enrich_cve(cve_id)
            if raw_data.get('state') != 'PUBLISHED': continue
            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            if not is_target: continue

            current_state = {
                "id": cve_id, "title": raw_data['title'], "cvss": raw_data['cvss'], "cvss_vector": raw_data['cvss_vector'],
                "is_kev": cve_id in collector.kev_set, "epss": collector.epss_cache.get(cve_id, 0.0),
                "description": raw_data['description'],
                "cwe": raw_data['cwe'], "references": raw_data['references'],
                "affected": raw_data['affected']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            should_alert, alert_reason = False, ""
            
            is_high_risk = False
            if current_state['cvss'] >= 7.0 or current_state['is_kev']: is_high_risk = True
            
            if last_record is None:
                should_alert, alert_reason = True, f"신규 취약점"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'):
                    should_alert, alert_reason, is_high_risk = True, "🚨 KEV 등재", True
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05:
                    should_alert, alert_reason, is_high_risk = True, "📈 EPSS 급증", True

            if should_alert:
                print(f"[!] 알림 발송: {cve_id} (HighRisk: {is_high_risk})")
                title_ko, desc_ko = generate_korean_summary(current_state)
                current_state['title_ko'] = title_ko
                current_state['desc_ko'] = desc_ko
                
                report_url = None
                if is_high_risk:
                    report_url = create_github_issue(current_state, alert_reason)
                
                notifier.send_alert(current_state, alert_reason, report_url)
                
                db.upsert_cve({
                    "id": cve_id, "cvss_score": current_state['cvss'], "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'], "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state, "updated_at": datetime.datetime.now().isoformat()
                })
            else:
                db.upsert_cve({"id": cve_id, "updated_at": datetime.datetime.now().isoformat()})
        except Exception as e:
            print(f"[ERR] {cve_id}: {e}")

if __name__ == "__main__":
    main()