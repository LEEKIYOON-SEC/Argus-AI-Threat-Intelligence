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
        # 여기서 스칼라를 정규화해 두면 요약 집계(비교·정렬·슬라이싱)가 None에 걸려
        # 통째로 실패하는 일이 없다 — 수집 시점 한 곳에서만 방어하면 충분하다.
        with self._lock:
            self._batch_results.append({
                "id": cve_data['id'],
                "title_ko": cve_data.get('title_ko') or cve_data.get('title') or 'N/A',
                "cvss": cve_data.get('cvss') or 0,
                "epss": cve_data.get('epss') or 0,
                "is_kev": cve_data.get('is_kev', False),
                "has_poc": cve_data.get('has_poc', False),
                # 요약의 '즉시 알림 N건' 집계(is_urgent)에 필요한 신호 — 빠지면 과소 집계된다
                "has_metasploit_module": cve_data.get('has_metasploit_module', False),
                "ssvc_exploitation": cve_data.get('ssvc_exploitation'),
                "reason": reason,
                "report_url": report_url,
            })
        logger.info(f"Slack 배치 수집: {cve_data['id']}")

    def send_alert(self, cve_data: Dict, reason: str, report_url: Optional[str] = None,
                   urgent: Optional[bool] = None) -> bool:
        """
        CVE 알림 처리:
        - 긴급(critical 티어) → 즉시 Slack 전송
        - 나머지 → 배치에 수집 (send_batch_summary에서 일괄 전송)

        urgent: 파이프라인이 이미 판정한 티어를 그대로 받는다(critical 여부). 미지정 시
        같은 신호 집합으로 자체 판정 — 판정 기준이 두 곳에서 어긋나지 않게 하기 위함이다.
        (과거엔 여기서만 'KEV or CVSS≥9'로 좁게 판정해, Metasploit 무기화·SSVC active·
         EPSS 급증 CVE가 GitHub Issue엔 '🔴 긴급'으로 실리면서 Slack은 조용한 상충이 있었다.)
        """
        self.collect_alert(cve_data, reason, report_url)

        if urgent is None:
            urgent = self.is_urgent(cve_data)
        if urgent:
            self._send_urgent_alert(cve_data, report_url)

        return True

    @staticmethod
    def is_urgent(cve_data: Dict) -> bool:
        """실제 악용·무기화 신호 또는 최상위 심각도 = 즉시 알림 대상.
        main._risk_tier의 critical 조건과 동일하게 유지할 것."""
        return bool(
            cve_data.get('is_kev')
            or cve_data.get('has_metasploit_module')
            or cve_data.get('ssvc_exploitation') == 'active'
            or (cve_data.get('epss') or 0) >= 0.1
            or (cve_data.get('cvss') or 0) >= 9.0
        )

    def _send_urgent_alert(self, cve_data: Dict, report_url: Optional[str] = None) -> bool:
        """긴급 CVE 즉시 알림 (실제 악용·무기화 신호 또는 CVSS 9+)"""
        try:
            # None 안전 추출 — 값이 명시적 null이면 .get의 기본값이 발동하지 않아
            # 비교 연산에서 TypeError가 나고, 예외를 삼키는 구조 탓에 긴급 알림이 통째로 유실된다.
            # (판정부 is_urgent는 이미 같은 방식으로 방어하고 있어 기준을 맞춘다)
            display_title = cve_data.get('title_ko') or cve_data.get('title') or 'N/A'
            cvss = cve_data.get('cvss') or 0
            epss = cve_data.get('epss') or 0

            # 긴급 배지 — '왜 긴급인지'를 배지로 그대로 보여준다
            badges = []
            if cve_data.get('is_kev'):
                badges.append("KEV")
            if cve_data.get('has_metasploit_module'):
                badges.append("무기화(MSF)")
            if cve_data.get('ssvc_exploitation') == 'active':
                badges.append("악용 진행형")
            if (epss or 0) >= 0.1:
                badges.append(f"EPSS {epss*100:.1f}%")
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

            # 요약 통계 — total은 '이번 실행 알림 전체'다(긴급 + 배치). 과거엔 이를
            # '긴급 알림'으로 표기해 실제 즉시 알림 건수와 어긋났다.
            urgent_n = sum(1 for r in self._batch_results if self.is_urgent(r))
            summary_lines = [
                f"*알림 {total}건* (즉시 알림 {urgent_n}건)",
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
    
    def send_pipeline_warning(self, title: str, detail: str) -> bool:
        """파이프라인 운영 경고 (격리 발생 등) — 조용한 실패로 묻히면 안 되는 상태 변화 통지."""
        try:
            return self._send_slack_with_retry({
                "blocks": [
                    {"type": "header", "text": {"type": "plain_text", "text": title}},
                    {"type": "section", "text": {"type": "mrkdwn", "text": detail}},
                ]
            }, "파이프라인 경고")
        except Exception as e:
            logger.error(f"파이프라인 경고 알림 실패: {e}")
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