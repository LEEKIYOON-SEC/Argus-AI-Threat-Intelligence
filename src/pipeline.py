from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytz

import risk
from logger import logger

KST = pytz.timezone('Asia/Seoul')

STATE_FIELDS = frozenset({
    "title", "title_ko", "description", "desc_ko", "cwe", "affected", "published",
    "cvss_vector",
    "references", "_nuclei_url", "_exploit_db_url",
    "is_kev", "is_kev_ransomware", "kev_due_date", "is_vulncheck_kev",
    "ssvc", "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
    "has_poc", "poc_urls", "has_public_exploit",
    "has_metasploit_module", "metasploit_modules",
    "has_nuclei_template", "nuclei_severity",
    "ai_discovered", "ai_program", "ai_detail", "ai_url", "analysis",
    "cvss", "cvss_version", "cvss_scores", "epss", "epss_percentile", "assigner",
    "tier", "fired_triggers",
})


@dataclass
class Outcome:
    cve_id: str
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


def build_state(cve_id: str, record: Dict, collector,
                epss_index: Optional[Dict[str, Tuple[float, float]]] = None
                ) -> Optional[Dict]:
    raw = collector.parse_record(cve_id, record)
    if raw.get('state') == 'ERROR':
        raise RuntimeError(f"{cve_id} 레코드 파싱 실패")
    if raw.get('state') != 'PUBLISHED':
        return None

    collector.enrich_cheap_signals(raw)

    epss_score, epss_pct = 0.0, 0.0
    if epss_index is not None and cve_id in epss_index:
        epss_score, epss_pct = epss_index[cve_id]
    elif cve_id in collector.epss_cache:
        epss_score = collector.epss_cache.get(cve_id, 0.0)
        epss_pct = collector.epss_percentile.get(cve_id, 0.0)

    if collector.kev_loaded:
        raw["is_kev"] = cve_id in collector.kev_set
        raw["kev_due_date"] = collector.kev_due_date.get(cve_id, "")
    if epss_index is not None or collector.epss_cache:
        raw["epss"] = epss_score
        raw["epss_percentile"] = epss_pct
    return raw


class RowCache:
    __slots__ = ("_db", "_rows", "_covered")


    def __init__(self, db, cve_ids=()):
        self._db = db
        self._rows: Dict[str, Dict] = {}
        self._covered: set = set()
        ids = list(dict.fromkeys(cve_ids))
        if ids:
            self._rows, self._covered = db.get_cves(ids)
            logger.info(f"기존 행 일괄 조회 {len(self._rows)}/{len(ids)}건 "
                        f"(개별 왕복 {len(self._covered)}회 절약)")


    def get(self, cve_id: str) -> Optional[Dict]:
        row = self._rows.get(cve_id)
        if row is not None:
            return row
        if cve_id in self._covered:
            return None
        return self._db.get_cve(cve_id)


    def forget(self, cve_id: str) -> None:
        self._rows.pop(cve_id, None)
        self._covered.discard(cve_id)


_CVSS_KEYS = ("cvss", "cvss_vector", "cvss_version", "cvss_scores")


def carry_forward(state: Dict, last: Optional[Dict]) -> Dict:
    if not isinstance(last, dict):
        return state
    for key in STATE_FIELDS:
        if key not in state and key in last:
            state[key] = last[key]
    if (float(state.get("cvss") or 0.0) <= 0.0 and not state.get("cvss_scores")
            and float(last.get("cvss") or 0.0) > 0.0):
        for key in _CVSS_KEYS:
            if key in last:
                state[key] = last[key]
    return state


def process(state: Dict, db, notifier, *, reason_prefix: str = "",
            make_report=None, rows: Optional["RowCache"] = None,
            silent: bool = False) -> Outcome:
    cve_id = state['id']
    try:
        last_row = rows.get(cve_id) if rows is not None else db.get_cve(cve_id)
        last = (last_row or {}).get('last_alert_state')
        carry_forward(state, last)
        decision = risk.decide(state, last)

        if decision.tier == risk.T3:
            if last is not None:
                _save(db, state, decision, last, alerted=False)
                if rows is not None:
                    rows.forget(cve_id)
                return Outcome(cve_id, "tracked", decision.tier, decision, state)
            return Outcome(cve_id, "skipped", decision.tier, decision, state)

        announce = decision.alert and not silent
        rules_info = None
        if announce and make_report is not None and not state.get('analysis'):
            analysis, rules_info = make_report(state, decision.reason)
            if analysis:
                state['analysis'] = analysis

        sent = True
        if announce:
            reason = f"{reason_prefix}{decision.reason}" if reason_prefix else decision.reason
            sent = notifier.send_alert(state, reason, tier=decision.tier) is not False
            if not sent:
                logger.error(f"{cve_id} Slack 전송 실패 — 발화 이력을 남기지 않는다 "
                             f"(다음 회차가 다시 알린다)")

        new_triggers = decision.new_triggers if sent else frozenset()
        if not _save(db, state, decision, last, alerted=announce and sent,
                     new_triggers=new_triggers, rules_info=rules_info):
            return Outcome(cve_id, "failed", decision.tier, decision, state)

        if rows is not None:
            rows.forget(cve_id)
        return Outcome(cve_id, "alerted" if (announce and sent) else "tracked",
                       decision.tier, decision, state)

    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        return Outcome(cve_id, "failed")


def _save(db, state: Dict, decision: risk.Decision, last: Optional[Dict],
          alerted: bool, rules_info: Optional[Dict] = None,
          new_triggers=None) -> bool:
    now = datetime.datetime.now(KST).isoformat()
    clean = {k: state[k] for k in STATE_FIELDS if k in state}
    clean["tier"] = decision.tier
    clean["fired_triggers"] = risk.merge_fired(
        last, decision.new_triggers if new_triggers is None else new_triggers)

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
    if rules_info:
        payload["has_official_rules"] = rules_info.get('has_official', False)
        payload["rules_snapshot"] = rules_info.get('rules')
        payload["last_rule_check_at"] = now
    return db.upsert_cve(payload)


def summarize(outcomes: List[Outcome]) -> str:
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
