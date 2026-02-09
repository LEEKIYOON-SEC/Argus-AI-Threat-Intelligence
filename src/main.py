import os
import datetime
import time
from google import genai
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

# AI Client 초기화
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

def is_target_asset(cve_description, cve_id):
    desc_lower = cve_description.lower()
    for target in config.TARGET_ASSETS:
        vendor, product = target.get('vendor', '').lower(), target.get('product', '').lower()
        if vendor == "*" and product == "*": return True, "All Assets (*)"
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    return False, None

def generate_report_content(cve_data, reason):
    prompt = f"보안 분석가로서 다음 CVE 정보를 한국어로 분석하여 리포트를 작성하세요.\nID: {cve_data['id']}\n정보: {cve_data['description']}\n사유: {reason}\n\n작성 규칙: 전문적인 한국어를 사용하고 기술 용어는 원문을 유지하며 Markdown 형식으로 작성하세요."
    try:
        response = client.models.generate_content(model=config.MODEL_PHASE_0, contents=prompt)
        return f"# 🛡️ Argus Intelligence Report\n**Target:** `{cve_data['id']}`\n**Alert:** {reason}\n\n--- \n## 🤖 AI 보안 분석 (Korean)\n**Engine:** `{config.MODEL_PHASE_0}`\n\n{response.text}\n\n--- \n## 📊 Risk Stats\n- **CVSS Score:** {cve_data['cvss']}\n- **EPSS Prob:** {cve_data['epss']*100:.2f}%\n- **KEV Listed:** {'🚨 YES' if cve_data['is_kev'] else 'No'}"
    except:
        return f"# 🛡️ Argus Report\nAI 분석 실패\n\n원문:\n{cve_data['description']}"

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
            
            # [필터 1] PUBLISHED 상태 확인 (REJECTED 제외)
            if raw_data.get('state') != 'PUBLISHED':
                print(f"[-] 스킵: {cve_id} (상태: {raw_data.get('state')})")
                continue

            # [필터 2] 자산 필터링
            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            if not is_target: continue

            current_state = {
                "id": cve_id, "cvss": raw_data['cvss'], "is_kev": cve_id in collector.kev_set,
                "epss": collector.epss_cache.get(cve_id, 0.0), "description": raw_data['description']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            should_alert, alert_reason = False, ""
            
            if last_record is None:
                should_alert, alert_reason = True, f"신규 취약점 ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'):
                    should_alert, alert_reason = True, "🚨 KEV 등재 확인"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05:
                    should_alert, alert_reason = True, "📈 EPSS 위험도 급증"

            if should_alert:
                print(f"[!] 알림 발송: {cve_id}")
                report_content = generate_report_content(current_state, alert_reason)
                report_url = db.upload_report(cve_id, report_content)
                notifier.send_alert(current_state, alert_reason, report_url['signedURL'])
                db.upsert_cve({
                    "id": cve_id, "cvss_score": current_state['cvss'], "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'], "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state, "updated_at": datetime.datetime.now().isoformat()
                })
            else:
                print(f"[-] 중복 스킵: {cve_id}")
                db.upsert_cve({
                    "id": cve_id, "cvss_score": current_state['cvss'], "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'], "updated_at": datetime.datetime.now().isoformat()
                })
        except Exception as e:
            print(f"[ERR] {cve_id}: {e}")

if __name__ == "__main__":
    main()