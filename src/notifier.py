import requests
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        clean_reason = reason.split(' (')[0] if ' (' in reason else reason
        emoji = "🚨" if "KEV" in reason else "🆕"
        
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Title:*\n{cve_data.get('title', 'N/A')}"}
                ]
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVSS Score:*\n{cve_data['cvss']}"},
                    {"type": "mrkdwn", "text": f"*EPSS Prob:*\n{cve_data['epss']*100:.2f}%"},
                    {"type": "mrkdwn", "text": f"*KEV Listed:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
                ]
            }
        ]

        # Target Matched 표시 (전체 * 일때는 생략)
        if "(" in reason and "*" not in reason:
            target_info = reason.split('(')[-1].replace(')', '')
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"🎯 *Target Asset:* {target_info}"}]
            })

        # [변경] 한글 요약본 출력 (없으면 원문 사용)
        description_text = cve_data.get('summary_ko', cve_data['description'])
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{description_text}"}
        })

        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📄 상세 분석 리포트 확인 (30일 유효)"},
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })

        requests.post(self.webhook_url, json={"blocks": blocks})