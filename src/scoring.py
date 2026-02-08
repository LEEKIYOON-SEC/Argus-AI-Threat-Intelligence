from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


def cvss_severity_from_score(score: float | None) -> str | None:
    """
    CVSS v3.x 일반 구간을 사용.
    - 0.0: NONE
    - 0.1–3.9: LOW
    - 4.0–6.9: MEDIUM
    - 7.0–8.9: HIGH
    - 9.0–10.0: CRITICAL
    """
    if score is None:
        return None
    try:
        s = float(score)
    except Exception:
        return None
    if s == 0.0:
        return "NONE"
    if 0.0 < s < 4.0:
        return "LOW"
    if 4.0 <= s < 7.0:
        return "MEDIUM"
    if 7.0 <= s < 9.0:
        return "HIGH"
    if 9.0 <= s <= 10.0:
        return "CRITICAL"
    return None


def is_cvss_high_or_more(score: float | None, severity: str | None) -> bool:
    sev = (severity or "").upper().strip()
    if sev in ("HIGH", "CRITICAL"):
        return True
    if score is None:
        return False
    try:
        s = float(score)
    except Exception:
        return False
    return s >= 7.0


@dataclass
class RiskFlags:
    # policy derived
    epss_immediate: bool
    epss_conditional_band: bool
    cvss_high_or_more: bool
    kev: bool

    # final notify intent (후속 dedup/변경분류에서 사용)
    should_notify: bool
    primary_reason: str


def compute_risk_flags(cfg, cve: dict) -> RiskFlags:
    """
    cve dict에 파생 필드도 기록해두는 방식(후속 단계에서 사용 편의).
    """
    epss = cve.get("epss_score")
    cvss = cve.get("cvss_score")
    sev = cve.get("cvss_severity")

    # cvss_severity가 없는데 score가 있으면 계산해 채움
    if (sev is None or sev == "") and cvss is not None:
        calc = cvss_severity_from_score(cvss)
        if calc:
            cve["cvss_severity"] = calc
            sev = calc

    kev = bool(cve.get("is_cisa_kev") or False)

    epss_immediate = False
    epss_band = False
    if epss is not None:
        try:
            e = float(epss)
            epss_immediate = e >= float(cfg.EPSS_IMMEDIATE)
            epss_band = (float(cfg.EPSS_CONDITIONAL) <= e < float(cfg.EPSS_IMMEDIATE))
        except Exception:
            epss_immediate = False
            epss_band = False

    cvss_high = is_cvss_high_or_more(cvss, sev)

    # 최종 알림 정책
    # - KEV는 항상 notify 후보
    # - EPSS>=0.1 notify 후보
    # - 0.01<=EPSS<0.1 AND CVSS High+ notify 후보
    should = kev or epss_immediate or (epss_band and cvss_high)

    if kev:
        reason = "CISA KEV 등재"
    elif epss_immediate:
        reason = f"EPSS ≥ {cfg.EPSS_IMMEDIATE}"
    elif epss_band and cvss_high:
        reason = f"{cfg.EPSS_CONDITIONAL} ≤ EPSS < {cfg.EPSS_IMMEDIATE} AND CVSS High+"
    else:
        reason = "정책상 알림 대상 아님"

    flags = RiskFlags(
        epss_immediate=epss_immediate,
        epss_conditional_band=epss_band,
        cvss_high_or_more=cvss_high,
        kev=kev,
        should_notify=should,
        primary_reason=reason,
    )

    # cve dict에 기록(후속 모듈에서 재사용)
    cve["risk_should_notify"] = flags.should_notify
    cve["risk_primary_reason"] = flags.primary_reason
    cve["risk_epss_immediate"] = flags.epss_immediate
    cve["risk_epss_band"] = flags.epss_conditional_band
    cve["risk_cvss_high_or_more"] = flags.cvss_high_or_more
    cve["risk_kev"] = flags.kev

    return flags
