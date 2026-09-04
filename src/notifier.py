import requests
import os
import re
import time
import threading
from typing import Dict, List, Optional

import risk
from logger import logger


def _cve_url(cve_id: str) -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None
    owner, name = repo.split("/", 1)
    return f"https://{owner.lower()}.github.io/{name}/cve.html?cve={cve_id}"


class NotifierError(Exception):
    pass


class SlackNotifier:
    MAX_RETRIES = 3
    RETRY_DELAYS = [2, 5, 10]


    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

        if not self.webhook_url:
            raise NotifierError("SLACK_WEBHOOK_URL이 설정되지 않음")

        self._batch_results: List[Dict] = []
        self._lock = threading.Lock()

        logger.info("Slack Notifier 초기화 완료")


    def _send_slack_with_retry(self, payload: dict, context: str = "Slack") -> bool:
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


    def collect_alert(self, cve_data: Dict, reason: str, tier: str) -> None:
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
                "url": _cve_url(cve_data['id']),
            })


    def send_alert(self, cve_data: Dict, reason: str, tier: str = risk.T2) -> bool:
        self.collect_alert(cve_data, reason, tier)
        if tier in risk.ALERTING_TIERS:
            return self._send_immediate(cve_data, reason, tier)
        return True


    @staticmethod
    def _fixed_target(cve_id: str) -> str:
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
        bits = []
        cvss = cve_data.get('cvss') or 0
        if cvss:
            ver = str(cve_data.get("cvss_version") or "").strip()
            bits.append(f"CVSS {cvss}" + (f" (v{ver})" if ver else ""))
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


    def _send_immediate(self, cve_data: Dict, reason: str, tier: str) -> bool:
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
            report_url = _cve_url(cve_data['id'])
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
                    link = f" <{r['url']}|상세>" if r.get('url') else ""
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


    def send_official_rule_update(self, cve_id: str, title: str, rules_info: Dict, dashboard_url: Optional[str] = None) -> bool:
        try:
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"✅ 공식 룰 발견: {cve_id}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\n\n이전 리포트에 공개 탐지 룰이 없던 취약점에 대해 *공식 검증된 룰*이 새로 발견되었습니다."}},
                {"type": "divider"}
            ]

            rule_count = 0

            if rules_info.get('sigma') and rules_info['sigma'].get('code'):
                rule_count += 1
                sigma_code = rules_info['sigma']['code'].strip()
                preview = sigma_code[:800] + "\n..." if len(sigma_code) > 800 else sigma_code
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*🟢 Sigma* ({rules_info['sigma']['source']})\n```{preview}```"}
                })

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

            if dashboard_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": "대시보드에서 보기"}, "url": dashboard_url, "style": "primary"}
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
            match = re.search(r'github\.com/([^/]+)/([^/]+)/issues/(\d+)', issue_url)
            if not match:
                logger.error(f"잘못된 Issue URL: {issue_url}")
                return False
            
            owner, repo, issue_number = match.groups()
            api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
            
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
