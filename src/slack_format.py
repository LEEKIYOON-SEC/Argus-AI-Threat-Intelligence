from __future__ import annotations

from typing import Optional, Sequence

from .i18n_ko import ko_severity, ko_attack_vector, ko_yesno


def _fmt(v) -> str:
    if v is None:
        return "N/A"
    return str(v)


def _shorten(text: str, max_len: int = 900) -> str:
    t = (text or "").strip()
    if len(t) <= max_len:
        return t
    return t[:max_len] + "…(생략)"


def _rule_snippet(rule_text: str, max_chars: int = 1200) -> str:
    """
    Slack에서 바로 복붙 가능한 수준을 유지하되,
    과도한 길이 폭발을 막기 위해 상한을 둔다.
    """
    t = (rule_text or "").strip()
    if len(t) <= max_chars:
        return t
    return t[:max_chars] + "\n…(truncated)"


def format_slack_message(
    *,
    cve: dict,
    alert_type: str,
    notify_reason: str,
    change_kind: str,
    report_link: str,
    top_validated_rules: Optional[Sequence[dict]] = None,
    include_rule_blocks_max: int = 3,
) -> str:
    """
    Slack 길이 폭발 방지:
    - 핵심 필드/판정/링크 중심
    - 룰은 (검증 PASS) 상위 N개만 “복붙 가능 블록”으로 포함
    - 나머지 룰 전체는 Report + rules.zip로 제공
    """
    cve_id = cve["cve_id"]
    cvss_score = cve.get("cvss_score")
    cvss_sev = ko_severity(cve.get("cvss_severity") or "")
    cvss_vec = cve.get("cvss_vector")
    av = ko_attack_vector(cve.get("attack_vector"))
    epss = cve.get("epss_score")
    epss_pct = cve.get("epss_percentile")
    kev = ko_yesno(bool(cve.get("is_cisa_kev") or False))
    kev_added = cve.get("kev_added_date") or "N/A"
    pub = cve.get("published_date") or (cve.get("date_published") or "N/A")
    upd = cve.get("last_modified_date") or (cve.get("date_updated") or "N/A")

    cwe = cve.get("cwe_ids") or []
    cwe_str = ", ".join(cwe[:20]) + (f" (+{len(cwe)-20} more)" if len(cwe) > 20 else "")
    refs = cve.get("references") or []
    refs_str = "\n".join([f"- {r}" for r in refs[:8]]) + (f"\n- ...(총 {len(refs)}개)" if len(refs) > 8 else "")

    desc_en = cve.get("description_en") or ""
    desc = _shorten(desc_en, 700)

    if alert_type == "NEW_CVE_PUBLISHED":
        title = "🆕 신규 CVE(PUBLISHED)"
    elif alert_type == "UPDATE_ESCALATION":
        title = "🚨 승격/재알림(위험도 상승)"
    else:
        title = "⚠️ 고위험 알림"

    lines: list[str] = []
    lines.append(f"*{title}*  `{cve_id}`")
    lines.append(f"- 트리거: {notify_reason} / 변경유형: {change_kind}")
    lines.append(f"- Published: {_fmt(pub)} / Updated: {_fmt(upd)}")
    lines.append(f"- CVSS: {_fmt(cvss_score)} / {cvss_sev}")
    if cvss_vec:
        lines.append(f"- Vector: `{cvss_vec}`")
    lines.append(f"- Attack Vector: {av}")
    lines.append(f"- EPSS: {_fmt(epss)} (pct {_fmt(epss_pct)})")
    lines.append(f"- CISA KEV: {kev} (added {kev_added})")
    if cwe_str:
        lines.append(f"- CWE: {cwe_str}")

    if desc:
        lines.append("\n*설명(원문 일부)*")
        lines.append(desc)

    if refs:
        lines.append("\n*참고(상위 일부)*")
        lines.append(refs_str)

    # 룰 블록(복붙 가능) — 검증 PASS 상위 N개만
    rule_items = list(top_validated_rules or [])
    if rule_items:
        lines.append(f"\n*검증 통과 룰(복붙 가능, 상위 {min(include_rule_blocks_max, len(rule_items))}개)*")
        for r in rule_items[:include_rule_blocks_max]:
            eng = r.get("engine", "unknown")
            src = r.get("source", "unknown")
            path = r.get("rule_path", "unknown")
            lines.append(f"- `{eng}` / {src} :: {path}")
            lines.append("```")
            lines.append(_rule_snippet(r.get("rule_text", ""), 1200))
            lines.append("```")

        if len(rule_items) > include_rule_blocks_max:
            lines.append(f"_나머지 {len(rule_items)-include_rule_blocks_max}개 검증 통과 룰은 Report 및 rules.zip에서 확인하세요._")

    lines.append("\n*상세 리포트(30일 링크)*")
    lines.append(report_link)

    lines.append("\n_참고: AI 모델은 웹검색 불가 전제이며, 리포트에 근거(Evidence Bundle)를 누적 구성합니다._")
    return "\n".join(lines)
