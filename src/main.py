import os
import datetime
from groq import Groq
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

# Groq 클라이언트
client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def is_target_asset(cve_description, cve_id):
    """자산 필터링 (assets.json active_rules 기준)"""
    desc_lower = cve_description.lower()
    
    for target in config.TARGET_ASSETS:
        vendor = target.get('vendor', '').lower()
        product = target.get('product', '').lower()
        
        # 1. 와일드카드 (*, *)
        if vendor == "*" and product == "*":
            return True, "All Assets (*)"
        # 2. 특정 벤더 전체 (*, *)
        if vendor in desc_lower and product == "*":
            return True, f"Vendor: {vendor}/*"
        # 3. 특정 제품
        if vendor in desc_lower and product in desc_lower:
            return True, f"Product: {vendor}/{product}"
            
    return False, None

def generate_report_content(cve_data, reason):
    """AI 한글 리포트 생성 (Phase 0 Model)"""
    selected_model = config.MODEL_PHASE_0
    
    prompt = f"""
    Role: Security Analyst.
    Task: Analyze this CVE and write a report in KOREAN.
    
    [Input]
    ID: {cve_data['id']}
    Desc: {cve_data['description']}
    Reason: {reason}
    
    [Rules]
    1. Language: Korean (한국어)
    2. Format: Markdown
    3. Structure:
       - **요약 (Summary)**: 1-2 sentences.
       - **상세 분석 (Analysis)**: Technical details based on description.
       - **대응 권고 (Mitigation)**: General advice.
    """

    try:
        chat_completion = client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=selected_model, 
            temperature=0.1, 
        )
        ai_analysis = chat_completion.choices[0].message.content
    except Exception as e:
        print(f"[WARN] AI Failed: {e}")
        ai_analysis = f"⚠️ **AI 분석 실패**\n\n원문: {cve_data['description']}"

    return f"""
# 🛡️ Argus Intelligence Report
**Target:** `{cve_data['id']}`
**Alert:** {reason}

---
## 🤖 AI Analysis (Korean)
**Model:** `{selected_model}`

{ai_analysis}

---
## 📊 Risk Stats
- **CVSS:** {cve_data['cvss']}
- **EPSS:** {cve_data['epss']*100:.2f}%
- **KEV:** {'🚨 YES' if cve_data['is_kev'] else 'No'}
"""

def main():
    print(f"[*] Argus Phase 0 Started (Model: {config.MODEL_PHASE_0})")
    
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    
    collector.fetch_kev()
    # 평소엔 hours=1 또는 2 권장, 테스트 시 hours=24
    target_cve_ids = collector.fetch_recent_cves(hours=2) 
    
    if not target_cve_ids:
        print("[*] No new CVEs.")
        return

    collector.fetch_epss(target_cve_ids)
    print(f"[*] Processing {len(target_cve_ids)} CVEs...")

    for cve_id in target_cve_ids:
        try:
            raw_data = collector.enrich_cve(cve_id)
            
            # 필터링
            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            if not is_target:
                continue 

            current_state = {
                "id": cve_id,
                "cvss": raw_data['cvss'],
                "epss": collector.epss_cache.get(cve_id, 0.0),
                "is_kev": cve_id in collector.kev_set,
                "description": raw_data['description']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            
            should_alert = False
            alert_reason = ""
            
            # 알림 결정 (신규 무조건)
            if last_record is None:
                should_alert = True
                alert_reason = f"🆕 New CVE ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'):
                    should_alert = True
                    alert_reason = "🚨 KEV Listed"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05:
                    should_alert = True
                    alert_reason = "📈 EPSS Surge"
                elif current_state['cvss'] >= 7.0 and last_state.get('cvss', 0) < 7.0:
                    should_alert = True
                    alert_reason = "⚠️ CVSS Escalated"

            if should_alert:
                print(f"[!] Alerting: {cve_id}")
                report_content = generate_report_content(current_state, alert_reason)
                report_url = db.upload_report(cve_id, report_content)
                notifier.send_alert(current_state, alert_reason, report_url['signedURL'])
                
                upsert_data = {
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state,
                    "updated_at": datetime.datetime.now().isoformat()
                }
                db.upsert_cve(upsert_data)
            else:
                # 알림 안 보내도 DB 상태는 최신화
                db.upsert_cve({
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "updated_at": datetime.datetime.now().isoformat()
                })
            
        except Exception as e:
            print(f"[ERR] {cve_id}: {e}")
            continue

if __name__ == "__main__":
    main()