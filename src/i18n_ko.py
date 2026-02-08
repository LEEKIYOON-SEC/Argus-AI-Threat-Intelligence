from __future__ import annotations


def ko_severity(sev: str) -> str:
    s = (sev or "").strip().upper()
    if s in ("CRITICAL", "CRIT"):
        return "치명적(Critical)"
    if s in ("HIGH",):
        return "높음(High)"
    if s in ("MEDIUM", "MODERATE"):
        return "중간(Medium)"
    if s in ("LOW",):
        return "낮음(Low)"
    if s in ("NONE", "UNKNOWN", ""):
        return "정보없음/미분류"
    return f"{sev} (원문)"


def ko_attack_vector(av: str | None) -> str:
    a = (av or "").strip().upper()
    if a == "NETWORK":
        return "네트워크(Network)"
    if a == "ADJACENT":
        return "인접 네트워크(Adjacent)"
    if a == "LOCAL":
        return "로컬(Local)"
    if a == "PHYSICAL":
        return "물리(Physical)"
    if a == "":
        return "정보없음"
    return f"{av} (원문)"


def ko_yesno(v: bool | None) -> str:
    return "예" if bool(v) else "아니오"
