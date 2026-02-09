import os
import datetime
from google import genai
from groq import Groq
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

# 1. Google AI Studio 설정 (GEMINI_API_KEY 환경변수 사용)
gemma_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# 2. Groq 설정 (Phase 1용)
groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def is_target_asset(cve_description, cve_id):
    """자산 필터링 (assets.json 기준)"""
    desc_lower = cve_description.lower()
    for target in config.TARGET_ASSETS:
        vendor = target.get('vendor', '').lower()
        product = target.get('product', '').lower()
        if vendor == "*" and product == "*": return True, "All Assets (*)"
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    return False, None

def generate_report_content(cve_data, reason):
    """
    Google AI Studio의 Gemma 3 모델을 사용하여 전문적인 한글 보안 리포트 생성
    """
    selected_model = config.MODEL_PHASE_0
    
    prompt = f"""
    당신은 숙련된 사이버 보안 분석가입니다. 다음 CVE 취약점 정보를 바탕으로 한국어 보안 권고문을 작성하세요.
    
    [입력 데이터]
    ID: {cve_data['id']}
    기술 설명: {cve_data['description']}
    탐지 사유: {reason}
    
    [작성 규칙]
    1. 반드시 한국어(Korean)로 자연스럽고 전문적인 톤으로 작성하세요.
    2. 'Remote Code Execution', 'Buffer Overflow'와 같은 보안 전문 용어는 번역하지 말고 원문을 유지하세요.
    3. 형식 (Markdown):
       - **핵심 요약**: 취약점의 성격과 위험도를 1~2문장으로 요약.
       - **상세 분석**: 공격 벡터 및 영향력 설명.
       - **대응 권고**: 패치 업데이트 등 일반적인 대응 방안.
    """

    try:
        # Gemma 3 모델 호출
        model = genai.GenerativeModel(selected_model)
        response = model.generate_content(prompt)
        ai_analysis = response.text
    except Exception as e:
        print(f"[WARN] Google AI Studio Failed ({selected_model}): {e}")
        ai_analysis = f"⚠️ **AI 분석 실패 (Gemma 3)**\n\n원문 내용:\n{cve_data['description']}"

    return f"""
# 🛡️ Argus Intelligence Report
**Target:** `{cve_data['id']}`
**Alert Reason:** {reason}

---
## 🤖 AI 보안 분석 (Korean)
**Engine:** `{selected_model}`

{ai_analysis}

---
## 📊 Risk Stats
- **CVSS Score:** {cve_data['cvss']}
- **EPSS Probability:** {cve_data['epss']*100:.2f}%
- **KEV Listed:** {'🚨 YES (CISA)' if cve_data['is_kev'] else 'No'}
"""

def main():
    print(f"[*] Argus Phase 0 가동 (모델: {config.MODEL_PHASE_0})")
    
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    
    collector.fetch_kev()
    # 2시간 주기로 안전하게 수집 (DB 중복 필터링 활용)
    target_cve_ids = collector.fetch_recent_cves(hours=2) 
    
    if not target_cve_ids:
        print("[*] 최근 2시간 내 새로운 CVE가 없습니다.")
        return

    collector.fetch_epss(target_cve_ids)
    print(f"[*] 분석 대상 취약점: {len(target_cve_ids)}건")

    for cve_id in target_cve_ids:
        try:
            raw_data = collector.enrich_cve(cve_id)
            
            # 자산 필터링 수행
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
            
            # 알림 조건 판단
            if last_record is None:
                should_alert = True
                alert_reason = f"🆕 신규 취약점 ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'):
                    should_alert = True
                    alert_reason = "🚨 KEV 등재 (공격 확인됨)"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05:
                    should_alert = True
                    alert_reason = "📈 EPSS 수치 급증"
                elif current_state['cvss'] >= 7.0 and last_state.get('cvss', 0) < 7.0:
                    should_alert = True
                    alert_reason = "⚠️ CVSS 등급 상향"

            if should_alert:
                print(f"[!] 알림 발송 중: {cve_id}")
                report_content = generate_report_content(current_state, alert_reason)
                report_url = db.upload_report(cve_id, report_content)
                notifier.send_alert(current_state, alert_reason, report_url['signedURL'])
                
                # DB 상태 업데이트
                db.upsert_cve({
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state,
                    "updated_at": datetime.datetime.now().isoformat()
                })
            else:
                # 상태만 최신화 (알림 중복 방지)
                db.upsert_cve({
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "updated_at": datetime.datetime.now().isoformat()
                })
            
        except Exception as e:
            print(f"[ERR] {cve_id} 처리 실패: {e}")
            continue

if __name__ == "__main__":
    main()