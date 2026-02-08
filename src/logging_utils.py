from __future__ import annotations

import logging
import os
import sys
from typing import Optional


def setup_logging(level: Optional[str] = None) -> None:
    """
    GitHub Actions/서버 어디서 실행해도 동일 포맷으로 남기기 위한 로거 설정.
    """
    lvl = (level or os.getenv("ARGUS_LOG_LEVEL", "INFO")).upper()
    resolved = getattr(logging, lvl, logging.INFO)

    logging.basicConfig(
        level=resolved,
        stream=sys.stdout,
        format="%(asctime)sZ | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
