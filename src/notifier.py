import requests
import os
import re
import time
import threading
from typing import Dict, List, Optional
from logger import logger

class NotifierError(Exception):
    """알림 관련 에러"""
    pass

class SlackNotifier:
    MAX_RETRIES = 3
    RETRY_DELAYS = [2, 5, 10]  # 초

    def __init__(self):
        """Slack Webhook 초기화"""
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

        if not self.webhook_url:
            raise NotifierError("SLACK_WEBHOOK_URL이 설정되지 않음")

        # 배치 알림용 결과 수집 (thread-safe)
        self._batch_results: List[Dict] = []
        self._lock = threading.Lock()

        logger.info("Slack Notifier 초기화 완료")

    def _send_slack_with_retry(self, payload: dict, context: str = "Slack") -> bool:
        """Slack webhook 전송 + 재시도 (최대 3회, 지수 백오프)"""
        for attempt in range(self.MAX_RETRIES):
            try:
                response = requests.post(self.webhook_url, json=payload, timeout=10)
                response.raise_for_status()
                return True
            except requests.exceptions.RequestException as e:
                delay = self.RETRY_DELAYS[attempt] if attempt < len(self.RETRY_DELAYS) else 10
                logger.warning(f"{context} 전송 실패 (시도 {attempt+1}/{self.MAX_RETRIES}): {e}")
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(delay)
                else:
                    logger.error(f"{context} 전송 최종 실패: {e}")
                    return False
        return False

    def collect_alert(self, cve_data: Dict, reason: str, report_url: Optional[str] = None) -> None:
        """개별 CVE 알림을 배치 결과에 수집 (thread-safe)"""
        with self._lock:
            self._batch_results.append({
                "id": cve_data['id'],
                "title_ko": cve_data.get('title_ko', cve_data.get('title', 'N/A')),
                "cvss": cve_data.get('cvss', 0),
                "epss": cve_data.get('epss', 0),
                "is_kev": cve_data.get('is_kev', False),
                "has_poc": cve_data.get('has_poc', False),
                "reason": reason,
                "report_url": report_url,
            })
        logger.info(f"Slack 배치 수집: {cve_data['id']}")

    def send_alert(self, cve_data: Dict, reason: str, report_url: Optional[str] = None) -> bool:
        """
        CVE 알림 처리:
        - KEV 등재 또는 CVSS 9.0+ → 즉시 Slack 전송 (긴급)
        - 나머지 → 배치에 수집 (send_batch_summary에서 일괄 전송)
        """
        self.collect_alert(cve_data, reason, report_url)

        # 긴급 알림: KEV 등재 또는 CVSS 9.0+
        is_urgent = cve_data.get('is_kev', False) or cve_data.get('cvss', 0) >= 9.0
        if is_urgent:
            self._send_urgent_alert(cve_data, reason, report_url)

        return True

    def _send_urgent_alert(self, cve_data: Dict, reason: str, report_url: Optional[str] = None) -> bool:
        """긴급 CVE 즉시 알림 (KEV 또는 CVSS 9+)"""
        try:
            display_title = cve_data.get('title_ko', cve_data.get('title', 'N/A'))
            cvss = cve_data.get('cvss', 0)
            epss = cve_data.get('epss', 0)

            # 긴급 배지
            badges = []
            if cve_data.get('is_kev'):
                badges.append("KEV")
            if cvss >= 9.0:
                badges.append(f"CVSS {cvss}")
            if cve_data.get('has_poc'):
                badges.append("PoC")
            badge_text = " | ".join(badges)

            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"🚨 긴급: {cve_data['id']}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text":
                    f"*{display_title}*\n\n"
                    f"*{badge_text}*  |  EPSS {epss*100:.2f}%"
                }},
            ]

            if report_url:
                blocks.append({
                    "type": "actions",
                    "elements": [{"type": "button", "text": {"type": "plain_text", "text": "상세 분석 리포트"}, "url": report_url, "style": "danger"}]
                })

            success = self._send_slack_with_retry({"blocks": blocks}, f"긴급 알림 ({cve_data['id']})")
            if success:
                logger.info(f"Slack 긴급 알림 전송: {cve_data['id']} ({badge_text})")
            return success

        except Exception as e:
            logger.error(f"Slack 긴급 알림 실패: {e}")
            return False

    def send_batch_summary(self, dashboard_url: Optional[str] = None, tracked_high: int = 0) -> bool:
        """수집된 CVE 결과를 한 번에 요약 전송.

        tracked_high: 이번 실행에서 Issue 없이 대시보드 추적만 시작한 High(CVSS 7~8.9
        단독) 건수 — 알림 노이즈 없이 규모는 파악되도록 요약에 집계한다."""
        if not self._batch_results and tracked_high == 0:
            logger.info("Slack 배치 알림: 전송할 CVE 없음")
            return True

        try:
            total = len(self._batch_results)
            high_risk = [r for r in self._batch_results if r['cvss'] >= 7.0]
            critical = [r for r in self._batch_results if r['cvss'] >= 9.0]
            kev_list = [r for r in self._batch_results if r['is_kev']]
            poc_list = [r for r in self._batch_results if r['has_poc']]

            # 헤더
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"🛡️ Argus CVE 탐지 요약 (알림 {total}건)"}},
            ]

            # 요약 통계
            summary_lines = [
                f"*긴급 알림:* {total}건",
                f"• 🔴 *Critical (CVSS 9+):* {len(critical)}건",
                f"• 🟠 *High Risk (CVSS 7+):* {len(high_risk)}건",
                f"• 🚨 *KEV 등재:* {len(kev_list)}건",
            ]
            if poc_list:
                summary_lines.append(f"• 🔥 *PoC 공개:* {len(poc_list)}건")
            if tracked_high:
                summary_lines.append(
                    f"• 📋 *High(CVSS 7~8.9) 추적 등록:* {tracked_high}건 — 대시보드에서 확인"
                )

            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "\n".join(summary_lines)}
            })

            blocks.append({"type": "divider"})

            # 고위험 CVE 목록 (최대 5개)
            if high_risk:
                high_risk.sort(key=lambda x: x['cvss'], reverse=True)
                lines = []
                for r in high_risk[:5]:
                    kev_badge = " 🚨KEV" if r['is_kev'] else ""
                    poc_badge = " 🔥PoC" if r['has_poc'] else ""
                    report_link = f" <{r['report_url']}|상세>" if r.get('report_url') else ""
                    lines.append(
                        f"• `{r['id']}` (CVSS {r['cvss']}){kev_badge}{poc_badge} - {r['title_ko'][:50]}{report_link}"
                    )
                if len(high_risk) > 5:
                    lines.append(f"  … 외 {len(high_risk) - 5}건")

                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": "*🔴 고위험 CVE:*\n" + "\n".join(lines)}
                })

            # 대시보드 링크
            if dashboard_url:
                blocks.append({
                    "type": "actions",
                    "elements": [{"type": "button", "text": {"type": "plain_text", "text": "📊 대시보드에서 전체 확인"}, "url": dashboard_url, "style": "primary"}]
                })

            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": "상세 분석은 웹 대시보드 또는 GitHub Issue에서 확인하세요."}]
            })

            success = self._send_slack_with_retry({"blocks": blocks}, "배치 요약")
            if success:
                logger.info(f"Slack 배치 요약 전송 완료: {total}건 (고위험 {len(high_risk)}건)")
                with self._lock:
                    self._batch_results = []
            return success

        except Exception as e:
            logger.error(f"배치 요약 생성 에러: {e}")
            return False
    
    def send_official_rule_update(self, cve_id: str, title: str, rules_info: Dict, original_report_url: Optional[str] = None) -> bool:
        try:
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"✅ 공식 룰 발견: {cve_id}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\n\n이전 리포트에 공개 탐지 룰이 없던 취약점에 대해 *공식 검증된 룰*이 새로 발견되었습니다."}},
                {"type": "divider"}
            ]

            rule_count = 0

            # Sigma
            if rules_info.get('sigma') and rules_info['sigma'].get('code'):
                rule_count += 1
                sigma_code = rules_info['sigma']['code'].strip()
                preview = sigma_code[:800] + "\n..." if len(sigma_code) > 800 else sigma_code
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🟢 Sigma* ({rules_info['sigma']['source']})\n```{preview}```"}
                })

            # Network (여러 개 - 모두 표시)
            if rules_info.get('network'):
                for net_rule in rules_info['network']:
                    if net_rule.get('code'):
                        rule_count += 1
                        engine = net_rule.get('engine', 'unknown').upper()
                        rule_code = net_rule['code'].strip()
                        preview = rule_code[:800] + "\n..." if len(rule_code) > 800 else rule_code
                        blocks.append({
                            "type": "section",
                            "text": {"type": "mrkdwn", "text": f"*🟢 {engine}* ({net_rule['source']})\n```{preview}```"}
                        })

            # Yara
            if rules_info.get('yara') and rules_info['yara'].get('code'):
                rule_count += 1
                yara_code = rules_info['yara']['code'].strip()
                preview = yara_code[:800] + "\n..." if len(yara_code) > 800 else yara_code
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🟢 Yara* ({rules_info['yara']['source']})\n```{preview}```"}
                })

            blocks.append({"type": "divider"})
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"총 {rule_count}개 엔진의 공식 룰 발견. 위 룰을 복사하여 보안 장비에 등록하세요."}]
            })

            # GitHub Issue 링크 (전체 룰 + 상세 분석)
            if original_report_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": "전체 룰 + 상세 리포트 보기"}, "url": original_report_url, "style": "primary"}
                    ]
                })

            success = self._send_slack_with_retry({"blocks": blocks}, f"공식 룰 알림 ({cve_id})")
            if success:
                logger.info(f"공식 룰 발견 알림 전송: {cve_id} ({rule_count}개 엔진)")
            return success

        except Exception as e:
            logger.error(f"공식 룰 알림 실패: {e}")
            return False
    
    def update_github_issue(self, issue_url: str, comment: str) -> bool:
        try:
            # URL 파싱
            match = re.search(r'github\.com/([^/]+)/([^/]+)/issues/(\d+)', issue_url)
            if not match:
                logger.error(f"잘못된 Issue URL: {issue_url}")
                return False
            
            owner, repo, issue_number = match.groups()
            api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
            
            # 댓글 작성
            headers = {
                "Authorization": f"token {os.environ.get('GH_TOKEN')}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            payload = {"body": comment}
            
            response = requests.post(api_url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"GitHub Issue 댓글 추가: {issue_url}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub 댓글 추가 실패: {e}")
            return False
        except Exception as e:
            logger.error(f"Issue 업데이트 에러: {e}")
            return False