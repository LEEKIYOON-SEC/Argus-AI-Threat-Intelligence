"""CVE 한 건을 판정하고 처리하는 공통 경로 — fast-lane과 bulk-lane이 함께 쓴다.

레인이 둘로 갈린 뒤 가장 위험한 것은 **두 레인의 판정이 갈라지는 것**이다. 그래서
'레코드를 상태로 바꾸고 → 판정하고 → 저장/알림한다'는 흐름을 한 곳에만 둔다.
레인은 '무엇을 언제 부르는가'만 다르고, 판정과 저장 형식은 여기서 하나로 강제된다.

━━ 저위험을 저장하지 않는다 ━━

T3(판정 신호 없음)은 DB에 아무것도 남기지 않는다. 예전에는 재처리 방지용 '마커' 행을
남겼는데, 이제 delta 피드가 new/updated를 직접 알려주므로 중복 판별에 DB가 필요 없다.
나중에 그 CVE에 신호가 붙으면 signal_snapshot이 소스 쪽에서 잡아 온다 — 우리 DB에
있었는지와 무관하게.
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytz

import risk
from logger import logger

KST = pytz.timezone('Asia/Seoul')

#: last_alert_state(JSONB)에 저장할 필드. DB 용량 최소화(불변 원칙 2) —
#: 대시보드 표시 + 다음 실행의 전이 판정에 필요한 것만 남긴다.
STATE_FIELDS = frozenset({
    # 대시보드 표시
    "title", "title_ko", "description", "desc_ko", "cwe", "affected", "published",
    "cvss_vector",
    # 위협 신호 (표시 + 판정)
    "is_kev", "is_kev_ransomware", "kev_due_date", "is_vulncheck_kev",
    "ssvc", "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
    "has_poc", "poc_urls", "has_public_exploit",
    "has_metasploit_module", "metasploit_modules",
    "has_nuclei_template", "nuclei_severity",
    # 판정 입력
    "cvss", "epss", "epss_percentile", "assigner",
    # 티어와 '이미 알린 트리거' — 반복 발화 억제의 핵심
    "tier", "fired_triggers",
})


@dataclass
class Outcome:
    """한 건의 처리 결과."""
    cve_id: str
    #: "alerted" | "tracked" | "skipped"(T3·비발행) | "failed"(재시도 대상)
    status: str
    tier: str = risk.T3
    decision: Optional[risk.Decision] = None
    state: Optional[Dict] = field(default=None, repr=False)

    @property
    def needs_retry(self) -> bool:
        return self.status == "failed"

    @property
    def alerted(self) -> bool:
        return self.status == "alerted"


# ──────────────────────────────────────────────────────────────────────────
# 레코드 → 상태
# ──────────────────────────────────────────────────────────────────────────
def build_state(cve_id: str, record: Dict, collector,
                epss_index: Optional[Dict[str, Tuple[float, float]]] = None
                ) -> Optional[Dict]:
    """cvelistV5 레코드 → 판정 가능한 상태 dict. **네트워크를 쓰지 않는다.**

    반환 None = 판정 대상이 아님(PUBLISHED 아님, 파싱 불가). 실패와 구분하려고
    호출부는 파싱 예외를 따로 잡는다.
    """
    raw = collector.parse_record(cve_id, record)
    if raw.get('state') == 'ERROR':
        raise RuntimeError(f"{cve_id} 레코드 파싱 실패")
    if raw.get('state') != 'PUBLISHED':
        return None

    # 메모리·캐시 조회만 (VulnCheck KEV, ExploitDB, Metasploit, nuclei)
    collector.enrich_cheap_signals(raw)

    epss_score, epss_pct = 0.0, 0.0
    if epss_index is not None and cve_id in epss_index:
        epss_score, epss_pct = epss_index[cve_id]
    elif cve_id in collector.epss_cache:
        epss_score = collector.epss_cache.get(cve_id, 0.0)
        epss_pct = collector.epss_percentile.get(cve_id, 0.0)

    raw.update({
        "is_kev": cve_id in collector.kev_set,
        "kev_due_date": collector.kev_due_date.get(cve_id, ""),
        "epss": epss_score,
        "epss_percentile": epss_pct,
    })
    return raw


# ──────────────────────────────────────────────────────────────────────────
# 판정 → 저장/알림
# ──────────────────────────────────────────────────────────────────────────
def process(state: Dict, db, notifier, *, reason_prefix: str = "",
            make_report=None) -> Outcome:
    """상태 하나를 판정하고 그 결과대로 저장·알림한다.

    make_report: 알림 대상일 때 GitHub Issue를 만드는 콜러블(state, reason) -> (url, rules_info).
        fast-lane은 None을 넘겨 Issue 없이 Slack만 즉시 보낸다 — 리포트는 AI 분석이
        필요해 느리고, 그 지연을 알림이 기다릴 이유가 없다. bulk-lane이 뒤이어 채운다.
    """
    cve_id = state['id']
    try:
        last_row = db.get_cve(cve_id)
        last = (last_row or {}).get('last_alert_state')
        decision = risk.decide(state, last)

        if decision.tier == risk.T3:
            # 저장하지 않는다. 이미 추적 중이던 행이 T3으로 내려온 경우만 티어를 갱신해
            # 화면에서 빠지게 한다 (신호가 철회된 CVE를 계속 띄워 두지 않는다).
            if last is not None:
                _save(db, state, decision, last, alerted=False)
                return Outcome(cve_id, "tracked", decision.tier, decision, state)
            return Outcome(cve_id, "skipped", decision.tier, decision, state)

        report_url = None
        rules_info = None
        if decision.alert and make_report is not None:
            report_url, rules_info = make_report(state, decision.reason)

        if decision.alert:
            reason = f"{reason_prefix}{decision.reason}" if reason_prefix else decision.reason
            notifier.send_alert(state, reason, report_url, tier=decision.tier)

        if not _save(db, state, decision, last, alerted=decision.alert,
                     report_url=report_url, rules_info=rules_info):
            # 저장 실패 = 대시보드 미반영 + 다음 실행에서 같은 알림 재발송 위험 →
            # failed로 남겨 워터마크가 붙잡고 재처리하게 한다.
            return Outcome(cve_id, "failed", decision.tier, decision, state)

        return Outcome(cve_id, "alerted" if decision.alert else "tracked",
                       decision.tier, decision, state)

    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        return Outcome(cve_id, "failed")


def _save(db, state: Dict, decision: risk.Decision, last: Optional[Dict],
          alerted: bool, report_url: Optional[str] = None,
          rules_info: Optional[Dict] = None) -> bool:
    """상태를 DB에 저장. 저장 형식은 여기 한 곳에서만 만든다."""
    now = datetime.datetime.now(KST).isoformat()
    clean = {k: state[k] for k in STATE_FIELDS if k in state}
    clean["tier"] = decision.tier
    # 이미 알린 트리거를 누적 저장한다 — 다음 실행이 '새로 켜진 것'만 보고 판단하므로
    # EPSS가 계단식으로 올라도 같은 CVE가 반복 발화하지 않는다.
    clean["fired_triggers"] = risk.merge_fired(last, decision.new_triggers)

    payload = {
        "id": state['id'],
        "cvss_score": state.get('cvss', 0.0),
        "epss_score": state.get('epss', 0.0),
        "is_kev": bool(state.get('is_kev')),
        "last_alert_state": clean,
        "updated_at": now,
    }
    if alerted:
        payload["last_alert_at"] = now
        # report_url은 값이 있을 때만 쓴다. fast-lane 알림은 Issue를 아직 안 만들었으므로
        # None인데, 그대로 저장하면 과거에 발행했던 리포트 링크를 지워버린다.
        if report_url:
            payload["report_url"] = report_url
    if rules_info:
        payload["has_official_rules"] = rules_info.get('has_official', False)
        payload["rules_snapshot"] = rules_info.get('rules')
        payload["last_rule_check_at"] = now
    return db.upsert_cve(payload)


# ──────────────────────────────────────────────────────────────────────────
# 요약 로그
# ──────────────────────────────────────────────────────────────────────────
def summarize(outcomes: List[Outcome]) -> str:
    """한 회차 결과를 한 줄로. 티어별 분포가 곧 '알림이 적정한가'의 지표다."""
    by_tier: Dict[str, int] = {}
    for o in outcomes:
        if o.status in ("alerted", "tracked"):
            by_tier[o.tier] = by_tier.get(o.tier, 0) + 1
    alerted = sum(1 for o in outcomes if o.alerted)
    failed = sum(1 for o in outcomes if o.needs_retry)
    skipped = sum(1 for o in outcomes if o.status == "skipped")
    tiers = " · ".join(f"{t} {by_tier[t]}" for t in (risk.T0, risk.T1, risk.T2)
                       if by_tier.get(t))
    return (f"판정 {len(outcomes)}건 → 알림 {alerted} · 추적 {sum(by_tier.values())}"
            f"{f' ({tiers})' if tiers else ''} · 미저장 {skipped} · 실패 {failed}")
