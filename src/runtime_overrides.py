from __future__ import annotations

import os
import logging
from typing import Any, Optional

from .settings_store import get_setting_text

log = logging.getLogger("argus.runtime_overrides")


def _get_db_text(cfg, key: str) -> Optional[str]:
    try:
        v = get_setting_text(cfg, key)
        if v is None:
            return None
        v = v.strip()
        return v if v != "" else None
    except Exception as e:
        log.info("settings_store error for key=%s: %s", key, e)
        return None


def _cast_int(s: str) -> Optional[int]:
    try:
        return int(s.strip())
    except Exception:
        return None


def _cast_float(s: str) -> Optional[float]:
    try:
        return float(s.strip())
    except Exception:
        return None


def _cast_bool(s: str) -> Optional[bool]:
    t = s.strip().lower()
    if t in ("1", "true", "yes", "y", "on"):
        return True
    if t in ("0", "false", "no", "n", "off"):
        return False
    return None


def _setattr_safe(cfg: Any, attr: str, value: Any) -> None:
    try:
        setattr(cfg, attr, value)
    except Exception as e:
        log.info("setattr failed cfg.%s=%r: %s", attr, value, e)


def apply_runtime_overrides(cfg) -> None:
    """
    Supabase(argus.settings) 값을 런타임에 cfg로 주입.
    - 기존 코드가 cfg 값을 참조하는 형태를 그대로 살리고, 누락 없이 정책 반영 가능.
    - 여기서 다루는 key들은 운영 중 조정 빈도가 높고 시스템 안정성에 직접 영향이 큼.
    """

    # --- GitHub OSINT 운영 파라미터 ---
    # DB keys: argus_gh_snippet_fetch_max / argus_gh_rule_candidates_max
    v = _get_db_text(cfg, "argus_gh_snippet_fetch_max")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_GH_SNIPPET_FETCH_MAX", max(0, vi))

    v = _get_db_text(cfg, "argus_gh_rule_candidates_max")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_GH_RULE_CANDIDATES_MAX", max(0, vi))

    # --- EPSS 정책 (DB로도 조정 가능하게 확장) ---
    # 기존 .yml env 값이 있더라도, DB 값이 있으면 우선.
    # keys: argus_epss_immediate / argus_epss_conditional
    v = _get_db_text(cfg, "argus_epss_immediate")
    if v is not None:
        vf = _cast_float(v)
        if vf is not None:
            _setattr_safe(cfg, "EPSS_IMMEDIATE", vf)

    v = _get_db_text(cfg, "argus_epss_conditional")
    if v is not None:
        vf = _cast_float(v)
        if vf is not None:
            _setattr_safe(cfg, "EPSS_CONDITIONAL", vf)

    # --- Slack 길이/룰 블록 수(운영 최적화) ---
    # key: argus_slack_rule_blocks_max
    v = _get_db_text(cfg, "argus_slack_rule_blocks_max")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_SLACK_RULE_BLOCKS_MAX", max(0, vi))

    # --- PDF 추출 파라미터(폭발 방지) ---
    # key: argus_pdf_max_pages / argus_pdf_max_chars
    v = _get_db_text(cfg, "argus_pdf_max_pages")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_PDF_MAX_PAGES", max(1, vi))

    v = _get_db_text(cfg, "argus_pdf_max_chars")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "ARGUS_PDF_MAX_CHARS", max(500, vi))

    # --- Storage TTL (Signed URL 만료 정책) ---
    # key: argus_report_ttl_days
    v = _get_db_text(cfg, "argus_report_ttl_days")
    if v is not None:
        vi = _cast_int(v)
        if vi is not None:
            _setattr_safe(cfg, "REPORT_TTL_DAYS", max(1, vi))

    # 운영자가 “DB가 우선 적용됐는지” 확인할 수 있도록 로그 힌트
    # (Slack이 아니라 run log에만 남기고 싶으면 logging 설정에 따라 조절)
    log.info(
        "Runtime overrides applied: GH_SNIPPET=%s GH_RULE_MAX=%s EPSS_IMM=%s EPSS_COND=%s SLACK_RULE_BLOCKS=%s PDF_PAGES=%s PDF_CHARS=%s TTL_DAYS=%s",
        getattr(cfg, "ARGUS_GH_SNIPPET_FETCH_MAX", None),
        getattr(cfg, "ARGUS_GH_RULE_CANDIDATES_MAX", None),
        getattr(cfg, "EPSS_IMMEDIATE", None),
        getattr(cfg, "EPSS_CONDITIONAL", None),
        getattr(cfg, "ARGUS_SLACK_RULE_BLOCKS_MAX", None),
        getattr(cfg, "ARGUS_PDF_MAX_PAGES", None),
        getattr(cfg, "ARGUS_PDF_MAX_CHARS", None),
        getattr(cfg, "REPORT_TTL_DAYS", None),
    )
