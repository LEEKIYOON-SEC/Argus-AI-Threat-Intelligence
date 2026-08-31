import requests
import os
import re
import time
import threading
from typing import Dict, List, Optional

import risk
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

    def collect_alert(self, cve_data: Dict, reason: str, tier: str,
                      report_url: Optional[str] = None) -> None:
        """개별 CVE 알림을 배치 요약용으로 수집 (thread-safe).

        여기서 스칼라를 정규화해 두면 요약 집계(비교·정렬·슬라이싱)가 None에 걸려
        통째로 실패하는 일이 없다 — 수집 시점 한 곳에서만 방어하면 충분하다."""
        with self._lock:
            self._batch_results.append({
                "id": cve_data['id'],
                "title_ko": cve_data.get('title_ko') or cve_data.get('title') or 'N/A',
                "cvss": cve_data.get('cvss') or 0,
                "epss": cve_data.get('epss') or 0,
                "epss_percentile": cve_data.get('epss_percentile') or 0,
                "is_kev": bool(cve_data.get('is_kev')),
                "tier": tier,
                "reason": reason,
                "report_url": report_url,
            })

    def send_alert(self, cve_data: Dict, reason: str, report_url: Optional[str] = None,
                   tier: str = risk.T2) -> bool:
        """알림 발송. 티어는 **파이프라인이 판정한 것을 그대로 받는다**.

        예전에는 여기서 is_urgent()로 다시 판정했다. 그래서 리포트에는 '🔴 긴급'인데
        Slack은 조용한 상충이 실제로 났다 — 같은 신호를 두 곳에서 해석하면 언젠가
        갈라진다. 판정의 주인은 risk.py 하나다.
        """
        self.collect_alert(cve_data, reason, tier, report_url)
        if tier in risk.ALERTING_TIERS:
            return self._send_immediate(cve_data, reason, tier, report_url)
        return True

    @staticmethod
    def _fixed_target(cve_id: str) -> str:
        """OSV 역인덱스가 아는 패치 목표 버전 한 줄. 없으면 빈 문자열.

        '무엇을 하라'가 없는 알림은 결국 사람이 다시 찾아봐야 한다. 이미 만들어 둔
        인덱스를 여기서 한 번 더 쓴다(공개 정적 파일이라 DB 비용 0)."""
        try:
            import report as report_mod
            pkgs = report_mod._package_index().get(cve_id) or {}
        except Exception:
            return ""
        picks = []
        for pkg, eco_map in sorted(pkgs.items()):
            for eco, fixes in sorted((eco_map or {}).items()):
                good = [f for f in (fixes or []) if f]
                if good:
                    picks.append(f"`{pkg}` {eco} → *{good[0]}*")
            if len(picks) >= 3:
                break
        if not picks:
            return ""
        more = " …" if len(pkgs) > len(picks) else ""
        return " / ".join(picks[:3]) + more

    @staticmethod
    def _attack_conditions(cve_data: Dict) -> str:
        """공격 조건을 사람 말로. 점수 하나보다 이게 판단을 빨리 만든다."""
        m = risk.parse_vector(cve_data.get('cvss_vector'))
        if not m:
            return ""
        parts = []
        av = {"N": "네트워크", "A": "인접 네트워크", "L": "로컬", "P": "물리 접근"}.get(m.get("AV"))
        if av:
            parts.append(av)
        if m.get("PR") == "N":
            parts.append("인증 불필요")
        elif m.get("PR") in ("L", "H"):
            parts.append("인증 필요")
        if m.get("UI") == "N":
            parts.append("사용자 관여 없음")
        elif m.get("UI") in ("R", "A", "P"):
            parts.append("사용자 관여 필요")
        if m.get("AC") == "L" or m.get("AT") == "N":
            parts.append("조건 단순")
        return " · ".join(parts)

    @staticmethod
    def _indicators(cve_data: Dict) -> str:
        """지표 한 줄. EPSS는 percentile을 함께 적는다 — 0.09가 상위 5%라는 걸
        숫자만 봐서는 알 수 없기 때문이다."""
        bits = []
        cvss = cve_data.get('cvss') or 0
        if cvss:
            bits.append(f"CVSS {cvss}")
        pct = cve_data.get('epss_percentile') or 0
        epss = cve_data.get('epss') or 0
        if pct:
            bits.append(f"EPSS {epss * 100:.1f}% (상위 {max(0.1, (1 - pct) * 100):.1f}%)")
        elif epss:
            bits.append(f"EPSS {epss * 100:.1f}%")
        if cve_data.get('has_metasploit_module'):
            bits.append("Metasploit 모듈")
        if cve_data.get('has_nuclei_template'):
            bits.append("nuclei 템플릿")
        if cve_data.get('ai_discovered'):
            bits.append(f"AI 발견({cve_data.get('ai_program', 'AI')})")
        if cve_data.get('has_public_exploit'):
            bits.append("ExploitDB")
        if cve_data.get('has_poc'):
            bits.append("PoC")
        return " · ".join(bits)

    def _send_immediate(self, cve_data: Dict, reason: str, tier: str,
                        report_url: Optional[str] = None) -> bool:
        """T0/T1 즉시 알림.

        판단에 필요한 것을 메시지 안에서 끝낸다 — 무엇이 바뀌었나 · 무엇에 영향 ·
        어디까지 올리면 되나 · 어떤 조건에서 공격되나 · 지표. 예전 메시지는 제목과
        배지뿐이라 결국 이슈를 열어봐야 했다."""
        try:
            cve_id = cve_data['id']
            title = cve_data.get('title_ko') or cve_data.get('title') or 'N/A'
            head = "🚨 즉시 대응" if tier == risk.T0 else "⚠️ 높음"

            lines = [f"*{title}*", ""]
            lines.append(f"*무엇이 바뀌었나* · {reason}")

            affected = [a for a in (cve_data.get('affected') or []) if isinstance(a, dict)]
            if affected:
                shown = []
                for a in affected[:2]:
                    vendor = str(a.get('vendor') or '').strip()
                    product = str(a.get('product') or '').strip()
                    versions = str(a.get('versions') or '').strip()
                    name = f"{vendor} {product}".strip() or product or vendor
                    if name and name.lower() not in ('unknown', 'n/a'):
                        shown.append(f"{name}" + (f" ({versions})" if versions and
                                                  versions != '정보 없음' else ""))
                if shown:
                    more = f" 외 {len(affected) - len(shown)}건" if len(affected) > len(shown) else ""
                    lines.append(f"*영향* · {' / '.join(shown)}{more}")

            target = self._fixed_target(cve_id)
            if target:
                lines.append(f"*패치 목표* · {target}")

            cond = self._attack_conditions(cve_data)
            if cond:
                lines.append(f"*공격 조건* · {cond}")

            ind = self._indicators(cve_data)
            if ind:
                lines.append(f"*지표* · {ind}")

            due = cve_data.get('kev_due_date')
            if due:
                lines.append(f"*CISA 조치 기한* · {due}")

            blocks = [
                {"type": "header",
                 "text": {"type": "plain_text", "text": f"{head}: {cve_id}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
            ]

            elements = []
            if report_url:
                elements.append({"type": "button", "style": "danger",
                                 "text": {"type": "plain_text", "text": "상세 리포트"},
                                 "url": report_url})
            elements.append({"type": "button",
                             "text": {"type": "plain_text", "text": "CVE 원문"},
                             "url": f"https://www.cve.org/CVERecord?id={cve_id}"})
            refs = [r for r in (cve_data.get('references') or []) if r]
            if refs:
                elements.append({"type": "button",
                                 "text": {"type": "plain_text", "text": "벤더 권고"},
                                 "url": refs[0]})
            blocks.append({"type": "actions", "elements": elements[:3]})

            # 출처 표기 의무가 있는 소스가 판정에 쓰였으면 반드시 함께 싣는다.
            credits = ["출처: CISA KEV · EPSS(FIRST.org)"]
            if cve_data.get('is_vulncheck_kev'):
                credits.append("This product uses VulnCheck KEV")
            if cve_data.get('has_nuclei_template'):
                credits.append("nuclei-templates(ProjectDiscovery, MIT)")
            if cve_data.get('ai_program') == "Anthropic CVD":
                credits.append("Anthropic Disclosure Ledger")
            blocks.append({"type": "context",
                           "elements": [{"type": "mrkdwn", "text": " · ".join(credits)}]})

            ok = self._send_slack_with_retry({"blocks": blocks}, f"즉시 알림 ({cve_id})")
            if ok:
                logger.info(f"Slack 즉시 알림: {cve_id} [{tier}] {reason}")
            return ok

        except Exception as e:
            logger.error(f"Slack 즉시 알림 실패: {e}")
            return False

    def send_batch_summary(self, dashboard_url: Optional[str] = None,
                           tracked: int = 0) -> bool:
        """한 회차 요약. 즉시 알림이 이미 나간 건들의 '전체 그림'을 한 번 더 준다.

        tracked: 알림 없이 대시보드 추적만 시작한 T2 건수 — 알림 노이즈를 늘리지 않으면서
        규모는 보이게 한다."""
        if not self._batch_results and not tracked:
            logger.debug("배치 요약: 보낼 것 없음")
            return True

        try:
            rows = list(self._batch_results)
            t0 = [r for r in rows if r.get('tier') == risk.T0]
            t1 = [r for r in rows if r.get('tier') == risk.T1]

            lines = [f"*알림 {len(rows)}건*"]
            if t0:
                lines.append(f"• 🚨 *T0 관측된 악용:* {len(t0)}건")
            if t1:
                lines.append(f"• ⚠️ *T1 무기화 임박:* {len(t1)}건")
            if tracked:
                lines.append(f"• 📋 *T2 관찰 등록:* {tracked}건 — 대시보드에서 확인")

            blocks = [
                {"type": "header",
                 "text": {"type": "plain_text", "text": f"🛡️ Argus 요약 (알림 {len(rows)}건)"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}},
            ]

            if rows:
                rows.sort(key=lambda r: (risk.tier_rank(r.get('tier', risk.T2)),
                                         -(r.get('cvss') or 0)))
                items = []
                for r in rows[:8]:
                    link = f" <{r['report_url']}|상세>" if r.get('report_url') else ""
                    items.append(f"• `{r['id']}` {r.get('reason', '')}"
                                 f" — {str(r.get('title_ko', ''))[:48]}{link}")
                if len(rows) > 8:
                    items.append(f"  … 외 {len(rows) - 8}건")
                blocks.append({"type": "divider"})
                blocks.append({"type": "section",
                               "text": {"type": "mrkdwn", "text": "\n".join(items)}})

            if dashboard_url:
                blocks.append({"type": "actions", "elements": [
                    {"type": "button", "style": "primary",
                     "text": {"type": "plain_text", "text": "📊 대시보드"},
                     "url": dashboard_url}]})

            ok = self._send_slack_with_retry({"blocks": blocks}, "배치 요약")
            if ok:
                logger.info(f"Slack 요약 전송: 알림 {len(rows)}건 · 추적 {tracked}건")
                with self._lock:
                    self._batch_results = []
            return ok

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