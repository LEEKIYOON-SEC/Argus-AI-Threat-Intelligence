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
    # references 가 빠져 있었다. 수집은 하는데 저장이 안 돼서, 알림 시점에는 'CVE 원문·
    # 벤더 권고' 버튼이 나오다가 리포트 보강(backfill_reports)이 저장된 state 로 다시
    # 만들면 참고 자료 절이 통째로 비었고, analyzer 에 넘기는 분석 입력에서도 사라졌다.
    "references", "_nuclei_url", "_exploit_db_url",
    "is_kev", "is_kev_ransomware", "kev_due_date", "is_vulncheck_kev",
    "ssvc", "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact",
    "has_poc", "poc_urls", "has_public_exploit",
    "has_metasploit_module", "metasploit_modules",
    "has_nuclei_template", "nuclei_severity",
    "ai_discovered", "ai_program", "ai_detail", "ai_url",
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

    raw.update({
        "is_kev": cve_id in collector.kev_set,
        "kev_due_date": collector.kev_due_date.get(cve_id, ""),
        "epss": epss_score,
        "epss_percentile": epss_pct,
    })
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


def process(state: Dict, db, notifier, *, reason_prefix: str = "",
            make_report=None, rows: Optional["RowCache"] = None,
            silent: bool = False) -> Outcome:
    # silent=True: Slack 도 last_alert_at 도 남기지 않는다. fired_triggers 는 기록하므로
    # 다음 실행에서 재알림이 나가지 않는다. 소급 채우기 전용.
    # last_alert_at 을 남기면 get_missing_report_candidates 가 그 행을 리포트 대상으로
    # 집어 GitHub Issue 를 대량 생성한다 (is_kev DESC 정렬이라 맨 앞에 선다).
    cve_id = state['id']
    try:
        last_row = rows.get(cve_id) if rows is not None else db.get_cve(cve_id)
        last = (last_row or {}).get('last_alert_state')
        decision = risk.decide(state, last)

        if decision.tier == risk.T3:
            if last is not None:
                _save(db, state, decision, last, alerted=False)
                if rows is not None:
                    rows.forget(cve_id)
                return Outcome(cve_id, "tracked", decision.tier, decision, state)
            return Outcome(cve_id, "skipped", decision.tier, decision, state)

        announce = decision.alert and not silent
        report_url = None
        rules_info = None
        if announce and make_report is not None:
            report_url, rules_info = make_report(state, decision.reason)

        if announce:
            reason = f"{reason_prefix}{decision.reason}" if reason_prefix else decision.reason
            notifier.send_alert(state, reason, report_url, tier=decision.tier)

        if not _save(db, state, decision, last, alerted=announce,
                     report_url=report_url, rules_info=rules_info):
            return Outcome(cve_id, "failed", decision.tier, decision, state)

        if rows is not None:
            rows.forget(cve_id)
        return Outcome(cve_id, "alerted" if announce else "tracked",
                       decision.tier, decision, state)

    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        return Outcome(cve_id, "failed")


def _save(db, state: Dict, decision: risk.Decision, last: Optional[Dict],
          alerted: bool, report_url: Optional[str] = None,
          rules_info: Optional[Dict] = None) -> bool:
    now = datetime.datetime.now(KST).isoformat()
    clean = {k: state[k] for k in STATE_FIELDS if k in state}
    clean["tier"] = decision.tier
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
        if report_url:
            payload["report_url"] = report_url
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
