from __future__ import annotations

import hashlib
import json
from typing import Any, Tuple

from .scoring import compute_risk_flags, is_cvss_high_or_more


def compute_payload_hash(payload: dict) -> str:
    """
    Slack/Report에 실릴 핵심 데이터로 payload hash 생성.
    - 정렬된 JSON으로 안정적 해시
    """
    s = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _float(x) -> float | None:
    try:
        return float(x)
    except Exception:
        return None


def classify_change(prev: dict | None, cve: dict) -> str:
    """
    이전 상태(prev)가 있을 때 변화 종류를 판정.
    - NO_PREV: 신규
    - ESCALATION: 위험 승격(KEV 추가, EPSS 임계치 상향, CVSS High+ 등)
    - UPDATE: 위험 자체는 유사하지만 주요 필드 변경(설명/벡터/레퍼런스 등)
    - NO_CHANGE: 변화 없음
    """
    if not prev:
        return "NO_PREV"

    # KEV 승격
    prev_kev = bool(prev.get("is_cisa_kev") or False)
    now_kev = bool(cve.get("is_cisa_kev") or False)
    if (not prev_kev) and now_kev:
        return "ESCALATION"

    # EPSS 임계치 승격(0.01, 0.1 구간 기준)
    prev_epss = _float(prev.get("epss_score"))
    now_epss = _float(cve.get("epss_score"))
    if prev_epss is not None and now_epss is not None:
        # 0.1 돌파
        if prev_epss < 0.1 and now_epss >= 0.1:
            return "ESCALATION"
        # 0.01 돌파
        if prev_epss < 0.01 and now_epss >= 0.01:
            return "ESCALATION"

    # CVSS 승격: High+로 변경
    prev_cvss = _float(prev.get("cvss_score"))
    now_cvss = _float(cve.get("cvss_score"))
    prev_sev = prev.get("cvss_severity")
    now_sev = cve.get("cvss_severity")
    if not is_cvss_high_or_more(prev_cvss, prev_sev) and is_cvss_high_or_more(now_cvss, now_sev):
        return "ESCALATION"

    # 주요 필드 업데이트 감지(알림 재전송 가능)
    keys = ["cvss_score", "cvss_vector", "cvss_severity", "attack_vector", "published_date", "last_modified_date"]
    for k in keys:
        if (prev.get(k) or None) != (cve.get(k) or None):
            return "UPDATE"

    # references/cwe 변화(리스트는 순서 영향을 줄이기 위해 set 비교)
    prev_refs = set(prev.get("references") or [])
    now_refs = set(cve.get("references") or [])
    if prev_refs != now_refs:
        return "UPDATE"

    prev_cwe = set(prev.get("cwe_ids") or [])
    now_cwe = set(cve.get("cwe_ids") or [])
    if prev_cwe != now_cwe:
        return "UPDATE"

    return "NO_CHANGE"


def should_notify(cfg, cve: dict, prev: dict | None) -> Tuple[bool, str]:
    """
    정책 + 중복 방지 결합.
    1) 정책상 알림대상인지 (compute_risk_flags)
    2) prev 대비 승격/업데이트가 있는지
    3) payload hash가 동일한 완전 중복인지
    """
    flags = compute_risk_flags(cfg, cve)

    # 정책상 알림대상이 아니면 즉시 false
    if not flags.should_notify:
        return False, flags.primary_reason

    # prev 없으면 신규 알림
    if not prev:
        return True, f"{flags.primary_reason} (신규)"

    change = classify_change(prev, cve)
    if change == "ESCALATION":
        return True, f"{flags.primary_reason} (승격)"
    if change == "UPDATE":
        # 기업 운영에서는 '업데이트'도 중요(벡터/레퍼런스/설명 변경 등)
        return True, f"{flags.primary_reason} (업데이트)"

    # NO_CHANGE인데 정책 알림대상인 경우:
    # - 이미 발송했으면 중복 방지
    # - 아직 발송 기록이 없다면 발송(예: 과거 데이터 주입/초기화 케이스)
    if not prev.get("last_notified_at"):
        return True, f"{flags.primary_reason} (초기 발송)"

    return False, f"{flags.primary_reason} (중복/변화없음)"
