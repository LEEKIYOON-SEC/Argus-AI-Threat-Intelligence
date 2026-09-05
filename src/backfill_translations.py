import os
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import config as cfg
import main as bulk
import state as pstate
from logger import logger
from store import create_store

DEADLINE_MINUTES = int(os.environ.get("BACKFILL_TRANSLATION_MINUTES", "50"))
PASSES = int(os.environ.get("BACKFILL_TRANSLATION_PASSES", "6"))


def run() -> int:
    started = time.time()
    deadline = started + DEADLINE_MINUTES * 60
    chain = " → ".join(m for m, _key in cfg.config.TRANSLATION_MODELS)

    logger.info("=" * 60)
    logger.info(f"한글 번역 백필 · {chain}")
    logger.info("=" * 60)

    if any(key.startswith("gemini") for _m, key in cfg.config.TRANSLATION_MODELS):
        logger.warning("이 작업은 Gemini 한도를 쓰지 않아야 한다 — "
                       "ARGUS_TRANSLATION_MODELS=gemma 를 설정하라")

    db = create_store()
    pstate._DB_HANDLE = db

    total = 0
    for n in range(1, PASSES + 1):
        if time.time() > deadline:
            logger.warning(f"⏰ 예산 도달 — {n - 1}회차에서 중단")
            break
        before = pstate.read_backfill_offset()
        done = bulk.translate_tracked(db, deadline)
        total += done
        after = pstate.read_backfill_offset()
        logger.info(f"[{n}/{PASSES}] 한글화 {done:,}건 · 스캔 창 {before:,} → {after:,}")
        if done == 0 and after == before:
            logger.info("더 진행되지 않는다 — 남은 대상이 없거나 한도가 소진됐다")
            break
        if bulk._translation_exhausted():
            logger.warning("일일 한도 소진 — 여기서 멈춘다 (창 위치는 저장돼 있다)")
            break

    logger.info("=" * 60)
    logger.info(f"번역 백필 완료 · {(time.time() - started) / 60:.1f}분 · "
                f"한글화 {total:,}건")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(run())
