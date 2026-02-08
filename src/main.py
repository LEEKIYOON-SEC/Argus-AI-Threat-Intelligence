from __future__ import annotations

import os
from datetime import datetime, timezone

from .logging_utils import setup_logging, get_logger
from .config import load_config
from .supabase_db import SupabaseDB
from .slack import post_slack

log = get_logger("argus.main")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def main() -> None:
    setup_logging()

    cfg = load_config()
    db = SupabaseDB(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)

    selftest = os.getenv("ARGUS_SELFTEST", "").strip().lower() in ("1", "true", "yes", "y", "on")

    try:
        # 1) RUN 기록(최소 작동성/권한 확인)
        db.log_run("RUN", True, "startup ok")

        # 2) 선택: Slack self-test (기본 OFF)
        if selftest:
            post_slack(
                cfg.SLACK_WEBHOOK_URL,
                "✅ Argus-AI-Threat Intelligence 셀프테스트: 실행/DB 기록 성공",
            )

        log.info("Startup OK. selftest=%s", selftest)

        # 다음 단계에서 여기부터:
        # - CVE.org PUBLISHED 수집
        # - KEV/EPSS enrich
        # - 정책 compute_risk_flags
        # - dedup/변경분류
        # - 공식 룰 수집/검증 + AI 생성/검증
        # - Storage Report 저장 + Signed URL
        # - Slack 본 알림 발송

    except Exception as e:
        # 실패 로그 남기기(가능한 경우)
        try:
            db.log_run("RUN", False, f"startup failed: {e}")
        except Exception:
            pass
        raise


if __name__ == "__main__":
    main()
