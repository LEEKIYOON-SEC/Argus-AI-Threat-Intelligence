import datetime
import os
import time
from typing import Dict, List, Optional, Tuple

import ai_provenance
import enrichment_sources
import feed
import package_index
import pipeline
import risk
import signal_snapshot
import state as pstate
from collector import Collector
from config import config
from database import ArgusDB
from logger import logger
from notifier import SlackNotifier
from rate_limiter import rate_limit_manager

def _deadline() -> float:
    return time.time() + config.PERFORMANCE.get("fast_deadline_minutes", 5) * 60


def _dashboard_url() -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None
    owner, name = repo.split("/", 1)
    return f"https://{owner.lower()}.github.io/{name}/"


def _load_signals(collector: Collector) -> Optional[Dict[str, Tuple[float, float]]]:
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    collector.ai_ledger = ai_provenance.load_anthropic_ledger()
    package_index.get()
    return enrichment_sources.load_epss_above(risk.EPSS_P_HIGH)


def _evaluate_changes(changes: List[feed.Change], collector: Collector, db: ArgusDB,
                      notifier: SlackNotifier, epss_index, deadline: float,
                      rows: Optional[pipeline.RowCache] = None
                      ) -> Tuple[List[pipeline.Outcome], Dict[str, datetime.datetime]]:
    outcomes: List[pipeline.Outcome] = []
    failed_at: Dict[str, datetime.datetime] = {}

    for i, change in enumerate(changes):
        if time.time() > deadline:
            logger.warning(f"⏰ 시간 예산 도달 — 잔여 {len(changes) - i}건은 "
                           f"다음 회차 (워터마크가 붙잡는다)")
            for rest in changes[i:]:
                failed_at[rest.cve_id] = rest.batch_at
            break

        if change.record is None:
            failed_at[change.cve_id] = change.batch_at
            continue
        try:
            st = pipeline.build_state(change.cve_id, change.record, collector, epss_index)
        except Exception as e:
            logger.warning(f"{change.cve_id} 상태 구성 실패: {e}")
            failed_at[change.cve_id] = change.batch_at
            continue
        if st is None:
            outcomes.append(pipeline.Outcome(change.cve_id, "skipped"))
            continue

        out = pipeline.process(st, db, notifier, rows=rows)
        outcomes.append(out)
        if out.needs_retry:
            failed_at[change.cve_id] = change.batch_at

    return outcomes, failed_at


def _sweep_signals(collector: Collector, db: ArgusDB, notifier: SlackNotifier,
                   epss_index, deadline: float,
                   rows: Optional[pipeline.RowCache] = None) -> List[pipeline.Outcome]:
    outcomes: List[pipeline.Outcome] = []
    cap = config.PERFORMANCE.get("snapshot_cap", 80)
    for diff in signal_snapshot.sweep(db, fast_only=True, cap=cap):
        if not diff.added:
            continue
        processed: List[str] = []
        for cve_id in diff.added:
            if time.time() > deadline:
                logger.warning(f"⏰ [{diff.source.label}] 시간 예산 도달 — "
                               f"나머지는 다음 회차")
                break
            record = feed.fetch_record(cve_id)
            if record is None:
                continue
            try:
                st = pipeline.build_state(cve_id, record, collector, epss_index)
            except Exception as e:
                logger.warning(f"{cve_id} 상태 구성 실패: {e}")
                continue
            if st is None:
                processed.append(cve_id)
                continue
            out = pipeline.process(st, db, notifier,
                                   reason_prefix=f"[{diff.source.label}] ", rows=rows)
            outcomes.append(out)
            if not out.needs_retry:
                processed.append(cve_id)
        signal_snapshot.commit(db, diff, processed)
    return outcomes


def _advance_watermark(horizon: datetime.datetime,
                       failed_at: Dict[str, datetime.datetime]) -> None:
    fails, quarantined = pstate.read_failure_state()
    max_fail = config.PERFORMANCE.get("max_consecutive_failures", 3)
    retry_h = config.PERFORMANCE.get("quarantine_retry_hours", 24)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    held = pstate.active_quarantine(quarantined, retry_h)
    newly = []
    for cve_id in failed_at:
        fails[cve_id] = fails.get(cve_id, 0) + 1
        if fails[cve_id] >= max_fail and cve_id not in quarantined:
            quarantined[cve_id] = now_iso
            newly.append(cve_id)
    if newly:
        logger.error(f"⛔ 연속 {max_fail}회 실패로 격리 {len(newly)}건: {newly[:5]} — "
                     f"워터마크 전진을 위해 제외 ({retry_h}h 후 자동 재시도)")

    blocking = [t for cid, t in failed_at.items()
                if cid not in held and cid not in quarantined]
    new_mark = min(blocking) - datetime.timedelta(seconds=1) if blocking else horizon
    if blocking:
        logger.info(f"실패 {len(blocking)}건 때문에 워터마크를 {new_mark:%m-%d %H:%M:%S}에서 멈춘다")

    stale = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
    quarantined = {k: v for k, v in quarantined.items() if pstate.iso_after(v, stale)}
    fails = {k: v for k, v in fails.items() if k in quarantined or k in failed_at}
    pstate.write_watermark(new_mark, failures=fails, quarantined=quarantined,
                           rpd=rate_limit_manager.export_rpd_state())


def run() -> None:
    started = time.time()
    logger.info("=" * 60)
    logger.info("Argus fast-lane 시작")
    logger.info("=" * 60)

    deadline = _deadline()
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    rate_limit_manager.import_rpd_state(pstate.read_rpd_state())

    epss_index = _load_signals(collector)

    watermark = pstate.read_watermark()
    changes, horizon = feed.changes_since(watermark)
    cap = config.PERFORMANCE.get("fast_max_changes", 1500)
    changes, horizon = feed.cap_by_batch(changes, cap, horizon)
    feed.fill_records(changes, workers=config.PERFORMANCE.get("max_workers", 4) * 2)

    rows = pipeline.RowCache(db, [c.cve_id for c in changes])
    outcomes, failed_at = _evaluate_changes(changes, collector, db, notifier,
                                            epss_index, deadline, rows)

    _advance_watermark(horizon, failed_at)

    if time.time() > deadline:
        logger.warning("⏰ 변경분 처리에 예산을 다 썼다 — 소스측 대조는 다음 회차로 넘긴다")
    else:
        outcomes += _sweep_signals(collector, db, notifier, epss_index, deadline, rows)

    tracked = sum(1 for o in outcomes if o.status == "tracked")
    notifier.send_batch_summary(dashboard_url=_dashboard_url(), tracked=tracked)
    logger.info(pipeline.summarize(outcomes))
    logger.info(f"fast-lane 완료 · {time.time() - started:.1f}초")


def main() -> None:
    try:
        run()
    except Exception as e:
        logger.error(f"fast-lane 최상위 실패: {e}", exc_info=True)
        try:
            SlackNotifier().send_pipeline_warning(
                "🔴 Argus fast-lane 실패", f"```{type(e).__name__}: {e}```")
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
