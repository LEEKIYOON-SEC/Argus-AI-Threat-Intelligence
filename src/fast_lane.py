"""fast-lane — 5분마다 돌며 '고위험만 빨리 알리는' 경로.

여기서 하지 않는 일이 중요하다: **AI 번역도, AI 심층 분석도, 탐지 룰 검색도 하지 않는다.**
전부 bulk-lane이 뒤이어 채운다. 예전 구조는 이 셋이 알림과 같은 실행에 묶여 있었고,
코드 주석에 그 결과가 남아 있다 — "번역이 38분 데드라인 직전까지 점유, 알림 5/31건만 발송".
알림이 무거운 작업 뒤에 줄을 서면 신속성은 구조적으로 나오지 않는다.

한 회차가 하는 일은 셋뿐이다.
  ① delta 피드로 바뀐 CVE를 받아(1 요청) 메모리 신호로 판정하고, T0/T1이면 Slack 즉시.
  ② 가벼운 신호 소스(CISA KEV · VulnCheck KEV)를 지난 회차와 대조해, 우리 DB에 없던
     CVE가 갑자기 악용 목록에 오른 경우를 잡는다.
  ③ 워터마크를 전진시킨다. 실패한 건 앞에서 멈춰 다음 회차가 다시 본다(누락 0).

정상 소요는 1~2분이다.
"""
import datetime
import os
import time
from typing import Dict, List, Optional, Tuple

import pytz

import enrichment_sources
import feed
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

KST = pytz.timezone('Asia/Seoul')


def _deadline() -> float:
    return time.time() + config.PERFORMANCE.get("fast_deadline_minutes", 5) * 60


def _dashboard_url() -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None
    owner, name = repo.split("/", 1)
    return f"https://{owner.lower()}.github.io/{name}/"


def _load_signals(collector: Collector) -> Optional[Dict[str, Tuple[float, float]]]:
    """판정에 필요한 신호를 메모리에 올린다. 전부 캐시가 있어 대개 즉시 끝난다."""
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    # ExploitDB·Metasploit·nuclei 인덱스는 enrich_cheap_signals가 첫 조회 때 적재한다.
    # EPSS는 판정 하한(p95)보다 낮은 구간을 들고 있어 봐야 트리거가 안 켜지므로 잘라 받는다
    # (실측 366,357건 → p90 이상 36,640건).
    return enrichment_sources.load_epss_above(risk.EPSS_P_HIGH)


def _evaluate_changes(changes: List[feed.Change], collector: Collector, db: ArgusDB,
                      notifier: SlackNotifier, epss_index, deadline: float
                      ) -> Tuple[List[pipeline.Outcome], Dict[str, datetime.datetime]]:
    """변경분을 판정한다. (결과, 실패한 CVE의 배치 시각) — 뒤엣것이 워터마크를 붙잡는다."""
    outcomes: List[pipeline.Outcome] = []
    failed_at: Dict[str, datetime.datetime] = {}

    for change in changes:
        if time.time() > deadline:
            logger.warning(f"⏰ 시간 예산 도달 — 잔여 {len(changes) - len(outcomes)}건은 "
                           f"다음 회차 (워터마크가 붙잡는다)")
            for rest in changes[len(outcomes):]:
                failed_at[rest.cve_id] = rest.batch_at
            break

        if change.record is None:
            # 레코드를 못 받았다 = 판정 불가. 워터마크가 붙잡아 다음 회차에 재시도.
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

        out = pipeline.process(st, db, notifier)
        outcomes.append(out)
        if out.needs_retry:
            failed_at[change.cve_id] = change.batch_at

    return outcomes, failed_at


def _sweep_signals(collector: Collector, db: ArgusDB, notifier: SlackNotifier,
                   epss_index, deadline: float) -> List[pipeline.Outcome]:
    """가벼운 신호 소스를 지난 회차와 대조해 새로 올라온 CVE를 처리한다.

    이 경로가 '저위험을 DB에 쌓아두지 않아도 되는' 이유다 — 우리가 그 CVE를 알고
    있었는지와 무관하게, 소스 쪽에서 새로 들어온 것을 잡아 온다."""
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
                continue          # 저장하지 않으므로 다음 회차에 다시 잡힌다
            try:
                st = pipeline.build_state(cve_id, record, collector, epss_index)
            except Exception as e:
                logger.warning(f"{cve_id} 상태 구성 실패: {e}")
                continue
            if st is None:
                processed.append(cve_id)      # 비발행 — 다시 볼 이유 없다
                continue
            out = pipeline.process(st, db, notifier,
                                   reason_prefix=f"[{diff.source.label}] ")
            outcomes.append(out)
            if not out.needs_retry:
                processed.append(cve_id)
        signal_snapshot.commit(db, diff, processed)
    return outcomes


def _advance_watermark(horizon: datetime.datetime,
                       failed_at: Dict[str, datetime.datetime]) -> None:
    """워터마크 전진 — 누락 0의 핵심.

    실패분이 있으면 그중 가장 이른 배치 시각 **앞에서** 멈춘다. 단, 매번 실패하는
    레코드 하나가 워터마크를 영구 고정해 파이프라인 전체를 세우는 것은 막아야 하므로,
    연속 N회 실패한 CVE는 격리해 계산에서 뺀다(기존 독약 레코드 방어 유지)."""
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

    # 상태 비대화 방지 — 격리 유효기간이 한참 지난 항목은 정리한다
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

    if not all(config.health_check().values()):
        logger.error("헬스체크 실패")
        return

    deadline = _deadline()
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    rate_limit_manager.import_rpd_state(pstate.read_rpd_state())

    epss_index = _load_signals(collector)

    # ── ① 변경분
    watermark = pstate.read_watermark()
    changes, horizon = feed.changes_since(watermark)
    cap = config.PERFORMANCE.get("fast_max_changes", 300)
    if len(changes) > cap:
        logger.warning(f"변경 {len(changes)}건 > 상한 {cap} — 오래된 순으로 {cap}건만 "
                       f"이번 회차에 처리 (나머지는 워터마크가 붙잡는다)")
        horizon = changes[cap - 1].batch_at
        changes = changes[:cap]
    feed.fill_records(changes, workers=config.PERFORMANCE.get("max_workers", 4) * 2)

    outcomes, failed_at = _evaluate_changes(changes, collector, db, notifier,
                                            epss_index, deadline)

    # ── ② 신호 소스 대조 (워터마크와 무관 — 실패해도 다음 회차가 다시 잡는다)
    outcomes += _sweep_signals(collector, db, notifier, epss_index, deadline)

    # ── ③ 워터마크
    _advance_watermark(horizon, failed_at)

    # ── ④ 요약
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
