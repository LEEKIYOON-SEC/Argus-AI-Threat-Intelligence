from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Dict, List

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import risk
from collector import flatten_ssvc
from database import ArgusDB
from logger import logger


#: 이번 수정으로 **새로 켜지는** 알림 트리거. 기본값은 이것만 발화 이력에 심는다.
SEED_DEFAULT = frozenset({"ssvc_active"})


def reconcile(state: Dict, seed_all: bool = False) -> Dict:
    """저장된 state 에서 SSVC 를 평탄화하고 등급·발화이력을 다시 맞춘다.

    네트워크를 쓰지 않는다 — 필요한 값이 이미 행 안에 있다. CISA vulnrichment 의 SSVC 는
    `ssvc` 중첩 딕셔너리로 저장돼 왔고, risk.evaluate 는 평탄한 `ssvc_exploitation` 만
    읽었다. 그래서 화면에는 'SSVC: active' 가 뜨는데 판정은 T3 인 행이 쌓였다.

    **fired_triggers 를 함께 채우는 것이 이 도구의 핵심이다.** 평탄화만 하고 두면, 그
    CVE 가 다음에 한 번이라도 바뀌는 순간 risk.decide 가 ssvc_active(T0)를 '처음 보는
    신호'로 읽고 Slack 을 쏜다. 실측 432건이 그 대상이라 순차적으로 터진다. 여기서
    미리 '이미 발화한 것'으로 기록해 두면 새로 관측되는 것만 알림이 나간다.

    기본값은 **이번 수정이 새로 켜는 트리거만** 심는다(SEED_DEFAULT). 지금 발화하는데
    이력에 없는 다른 트리거(kev·metasploit 등)도 실측 480여 건 있는데, 그건 별개의
    미진단 상태라 여기서 조용히 덮으면 나가야 할 알림을 영영 막는다. 전부 맞추려면
    seed_all=True 를 명시한다.
    """
    new = dict(state)
    flatten_ssvc(new)

    verdict = risk.evaluate(new)
    new["tier"] = verdict.tier
    seed = verdict.alerting_triggers
    if not seed_all:
        seed = seed & SEED_DEFAULT
    new["fired_triggers"] = risk.merge_fired(state, seed)
    return new


def run(dry_run: bool, seed_all: bool = False) -> int:
    started = time.time()
    db = ArgusDB()

    rows = db.tracked_states()
    if not rows:
        logger.error("행을 하나도 읽지 못했다 — 중단 (조회 실패를 '없음'으로 읽지 않는다)")
        return 1
    logger.info(f"행 {len(rows):,}건 조회")

    updates: List[Dict] = []
    tier_moves: Dict[str, int] = {}
    seeded: Dict[str, int] = {}
    flattened = 0

    for row in rows:
        cve_id = row.get("id")
        state = row.get("last_alert_state")
        if not cve_id or not isinstance(state, dict):
            continue
        new = reconcile(state, seed_all=seed_all)
        if new == state:
            continue

        if any(new.get(k) and not state.get(k) for k in
               ("ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact")):
            flattened += 1
        before, after = str(state.get("tier") or risk.T3), new["tier"]
        if before != after:
            tier_moves[f"{before}→{after}"] = tier_moves.get(f"{before}→{after}", 0) + 1
        for key in set(new["fired_triggers"]) - set(state.get("fired_triggers") or []):
            seeded[key] = seeded.get(key, 0) + 1

        updates.append({"id": cve_id, "last_alert_state": new})

    if dry_run:
        ok = 0
    else:
        # updated_at 은 건드리지 않는다 — 보존 정책이 그 값으로 나이를 센다.
        ok = db.bulk_save_states(updates, "SSVC 정합")
        if ok:
            db.request_full_export()

    logger.info("=" * 60)
    logger.info(f"SSVC 정합{' 예행연습' if dry_run else ' 완료'}: 평탄화 {flattened:,} · "
                + (f"저장 대상 {len(updates):,}건 (저장 안 함)" if dry_run
                   else f"저장 {ok:,}/{len(updates):,}건"))
    if tier_moves:
        logger.info("등급 이동: " + " · ".join(f"{k} {v:,}" for k, v in sorted(tier_moves.items())))
    if seeded:
        logger.info("발화 이력에 미리 채운 트리거(=이만큼의 알림을 막았다): "
                    + " · ".join(f"{k} {v:,}" for k, v in sorted(seeded.items())))
    logger.info("Slack 알림 없음 · last_alert_at 미기록 — 이 도구는 notifier 를 부르지 않는다")
    logger.info(f"소요 {time.time() - started:.1f}초")
    logger.info("=" * 60)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="저장된 행의 SSVC 를 판정이 읽는 형태로 펴고 등급·발화이력을 소급 정합")
    ap.add_argument("--dry-run", action="store_true",
                    help="전부 계산만 하고 저장하지 않는다")
    ap.add_argument("--seed-all", action="store_true",
                    help="지금 발화하는 알림 트리거를 전부 이력에 심는다 (기본은 이번 "
                         "수정이 새로 켜는 ssvc_active 만 — 나머지는 별개 사안이라 "
                         "여기서 덮으면 나가야 할 알림을 막는다)")
    args = ap.parse_args()
    try:
        return run(args.dry_run, seed_all=args.seed_all)
    except Exception as e:
        logger.error(f"SSVC 정합 실패: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
