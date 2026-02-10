import os
import datetime
import time
import json
import requests
import textwrap
from google import genai
from google.genai import types
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# CVSS 매핑 테이블
CVSS_MAP = {
    "AV:N": "네트워크 (Network)", "AV:A": "인접 (Adjacent)", "AV:L": "로컬 (Local)", "AV:P": "물리적 (Physical)",
    "AC:L": "낮음 (Low)", "AC:H": "높음 (High)",
    "PR:N": "없음 (None)", "PR:L": "낮음 (Low)", "PR:H": "높음 (High)",
    "UI:N": "없음 (None)", "UI:R": "필수 (Required)",
    "S:U": "변경 없음 (Unchanged)", "S:C": "변경됨 (Changed)",
    "C:H": "높음 (High)", "C:L": "낮음 (Low)", "C:N": "없음 (None)",
    "I:H": "높음 (High)", "I:L": "낮음 (Low)", "I:N": "없음 (None)",
    "A:H": "높음 (High)", "A:L": "낮음 (Low)", "A:N": "없음 (None)"
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
    mapping_labels = {
        "AV": "공격 경로 (Vector)", "AC": "복잡성 (Complexity)", "PR": "필요 권한 (Privileges)",
        "UI": "사용자 관여 (User Interaction)", "S": "범위 (Scope)", 
        "C": "기밀성 (Confidentiality)", "I": "무결성 (Integrity)", "A": "가용성 (Availability)"
    }
    for part in parts:
        if ':' in part:
            key, val = part.split(':')
            full_key = f"{key}:{val}"
            label = mapping_labels.get(key, key)
            desc = CVSS_MAP.get(full_key, val)
            if key in mapping_labels:
                mapped_parts.append(f"• **{label}:** {desc}")
    return "<br>".join(mapped_parts)

def create_github_issue(cve_data, reason):
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not repo: return None

    # AI 상세 분석
    prompt = f"""
    Analyze this CVE in Korean.
    Title: {cve_data['title']}
    Desc: {cve_data['description']}
    
    Output JSON (Strict):
    {{
        "summary": "Detailed summary",
        "vector_analysis": "Explain attack vector scenarios details",
        "impact": "Detailed impact analysis",
        "mitigation": ["Step 1", "Step 2"]
    }}
    """
    ai_summary, ai_vector_analysis, ai_impact, ai_mitigation = "분석 대기", "정보 없음", "정보 없음", ["정보 없음"]
    try:
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                safety_settings=[types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE")]
            )
        )
        data = json.loads(response.text)
        ai_summary = data.get("summary", "-")
        ai_vector_analysis = data.get("vector_analysis", "-")
        ai_impact = data.get("impact", "-")
        ai_mitigation = data.get("mitigation", [])
    except: pass

    # 데이터 준비
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    cce_str = ", ".join(cve_data['cce']) if cve_data['cce'] else "N/A"
    
    score = cve_data['cvss']
    color = "lightgrey"
    if score >= 9.0: color = "red" # 9.0 이상 빨강
    elif score >= 7.0: color = "orange"
    elif score >= 4.0: color = "yellow"
    elif score > 0: color = "green"
    
    # [수정] 뱃지 URL 공백 제거 및 인코딩 방지
    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{cve_data['epss']*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data['is_kev'] else 'No'}-{'red' if cve_data['is_kev'] else 'lightgrey'})"

    affected_rows = ""
    for item in cve_data.get('affected', []):
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} |\n"
    if not affected_rows: affected_rows = "| - | - | - |"

    mitigation_list = "\n".join([f"- {m}" for m in ai_mitigation])
    ref_list = "\n".join([f"- {r}" for r in cve_data['references']])
    vector_details = parse_cvss_vector(cve_data.get('cvss_vector', 'N/A'))

    # [핵심 수정] textwrap.dedent를 사용하여 들여쓰기 문제를 원천 차단
    # 마크다운 본문을 맨 앞으로 당겨서 작성
    body = f"""# 🛡️ {cve_data['title_ko']}

> **Detected:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}
> **Reason:** {reason}

{badges}
**CWE:** {cwe_str} | **CCE:** {cce_str}

## 📦 영향 받는 자산 (Affected Assets)
| Vendor | Product | Versions |
| :--- | :--- | :--- |
{affected_rows}

## 🔍 취약점 분석 (Analysis)
| 항목 | 내용 |
| :--- | :--- |
| **요약** | {ai_summary} |
| **영향도** | {ai_impact} |

### 🏹 공격 벡터 (Attack Vector)
| 항목 | 내용 |
| :--- | :--- |
| **공식 벡터** | `{cve_data.get('cvss_vector', 'N/A')}` |
| **상세 분석** | {vector_details} |
| **AI 시나리오** | {ai_vector_analysis} |

## 🛡️ 대응 방안 (Mitigation)
{mitigation_list}

## 🔗 참고 자료 (References)
{ref_list}
"""

    url = f"https://api.github.com/repos/{repo}/issues"
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}
    payload = {"title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}", "body": body, "labels": ["security", "cve"]}
    
    resp = requests.post(url, headers=headers, json=payload)
    if resp.status_code == 201: return resp.json().get("html_url")
    else: return None

def main():
    print(f"[*] Argus Phase 0 시작 (모델: {config.MODEL_PHASE_0})")
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

            clean_match_info = match_info.replace("All Assets (*)", "Global").replace("(*)", "").strip()

            current_state = {
                "id": cve_id, "title": raw_data['title'], "cvss": raw_data['cvss'], "cvss_vector": raw_data['cvss_vector'],
                "is_kev": cve_id in collector.kev_set, "epss": collector.epss_cache.get(cve_id, 0.0),
                "description": raw_data['description'],
                "cwe": raw_data['cwe'], "references": raw_data['references'],
                "affected": raw_data['affected'], "cce": raw_data['cce']
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