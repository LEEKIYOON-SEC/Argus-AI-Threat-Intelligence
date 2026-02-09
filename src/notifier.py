import requests
import json
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        """Slack Block Kit 메시지 전송"""
        
        # 아이콘 및 색상 설정
        emoji = "⚠️"
        color = "#ffcc00" # Yellow
        if "KEV" in reason:
            emoji = "🚨"
            color = "#ff0000" # Red
        elif "EPSS" in reason and cve_data['epss'] >= 0.1:
             emoji = "🔥"
             color = "#ff5500" # Orange

        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {reason}: {cve_data['id']}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVSS Score:*\n{cve_data['cvss']}"},
                    {"type": "mrkdwn", "text": f"*EPSS Probability:*\n{cve_data['epss']} ({cve_data['epss']*100:.1f}%)"},
                    {"type": "mrkdwn", "text": f"*KEV Listed:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
                    {"type": "mrkdwn", "text": f"*Source:*\ncve.org"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{cve_data['description'][:200]}..."
                }
            }
        ]

        # 리포트 버튼 (Signed URL)
        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text",
                            "text": "📄 상세 분석 리포트 확인 (30일 유효)"
                        },
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })

        payload = {"blocks": blocks}
        try:
            requests.post(self.webhook_url, json=payload)
        except Exception as e:
            print(f"[ERR] Slack send failed: {e}")