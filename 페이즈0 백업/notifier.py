import requests
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        clean_reason = reason.split(' (')[0] if ' (' in reason else reason
        emoji = "🚨" if "KEV" in reason else "🆕"
        
        display_title = cve_data.get('title_ko', cve_data.get('title', 'N/A'))
        display_desc = cve_data.get('desc_ko', cve_data.get('summary_ko', cve_data['description']))
        cwe_info = ", ".join(cve_data.get('cwe', [])) if cve_data.get('cwe') else "N/A"

        affected_text = "정보 없음"
        if cve_data.get('affected'):
            first = cve_data['affected'][0]
            affected_text = f"• *Vendor:* {first['vendor']}\n• *Product:* {first['product']}\n• *Versions:* {first['versions']}"
            if len(cve_data['affected']) > 1: affected_text += f"\n(외 {len(cve_data['affected'])-1}건)"

        stats_fields = [
            {"type": "mrkdwn", "text": f"*CVSS:*\n{cve_data['cvss']}"},
            {"type": "mrkdwn", "text": f"*EPSS:*\n{cve_data['epss']*100:.2f}%"},
            {"type": "mrkdwn", "text": f"*KEV:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
            {"type": "mrkdwn", "text": f"*CWE:*\n{cwe_info}"},
        ]

        # [수정] 레퍼런스 링크 추가
        ref_text = ""
        if cve_data.get('references'):
            links = cve_data['references'][:3] # 최대 3개
            ref_text = "\n\n*🔗 References:*\n" + "\n".join([f"• <{r}|{r}>" for r in links])

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Title:*\n*{display_title}*"}},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": affected_text}},
            {"type": "divider"},
            {"type": "section", "fields": stats_fields},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Description:*\n{display_desc}{ref_text}"}}
        ]

        if "(" in reason and "*" not in reason:
            target_info = reason.split('(')[-1].replace(')', '')
            blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"🎯 *Target Asset:* {target_info}"}]})
        
        # [수정] 버튼 이름 변경 및 조건부 표시
        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [{"type": "button", "text": {"type": "plain_text", "text": "AI 상세 분석 리포트"}, "url": report_url, "style": "primary"}]
            })

        requests.post(self.webhook_url, json={"blocks": blocks})