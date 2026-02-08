from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .patch_intel import PatchFinding


def _norm(text: str) -> str:
    t = (text or "").strip()
    t = re.sub(r"[ \t]{2,}", " ", t)
    t = re.sub(r"\n{3,}", "\n\n", t)
    return t.strip()


def _clip(text: str, max_chars: int) -> str:
    t = _norm(text)
    if len(t) <= max_chars:
        return t
    return t[:max_chars] + "\n...(truncated)"


def build_evidence_bundle_text(
    *,
    cfg,
    cve: dict,
    patch_findings: List[PatchFinding],
    official_rules_summary_lines: List[str],
    ai_rule_generation_notes: Optional[str] = None,
    max_total_chars: int = 22000,
) -> str:
    """
    Llama-4-maverick 웹검색 불가 전제를 강제하기 위한 Evidence Bundle 생성.
    - URL은 참고로만 포함 가능하지만, '내용'은 반드시 텍스트로 포함하는 것을 목표로 함
    - 패치/권고 페이지는 HTML → 텍스트로 정규화한 extracted_text를 포함
    - 룰 생성은 Evidence Bundle만으로 재현 가능해야 함

    max_total_chars:
      - 모델 입력 토큰 폭발 방지(기업 운영 안정성)
    """
    parts: List[str] = []

    # 1) 정책/판정 기준(고정)
    parts.append("## Policy")
    parts.append(f"- EPSS >= {cfg.EPSS_IMMEDIATE}: immediate alert")
    parts.append(f"- {cfg.EPSS_CONDITIONAL} <= EPSS < {cfg.EPSS_IMMEDIATE}: alert only if CVSS High+")
    parts.append("- Exclude CVE state=REJECTED; include PUBLISHED only (datePublished exists).")
    parts.append("- Sigma MUST be provided. Network vs Host rules are routed by attack vector/evidence.")
    parts.append("")

    # 2) CVE 핵심 메타
    parts.append("## CVE Core")
    parts.append(f"- CVE: {cve.get('cve_id')}")
    parts.append(f"- Published: {cve.get('date_published')}")
    parts.append(f"- Updated: {cve.get('date_updated')}")
    parts.append(f"- CVSS: {cve.get('cvss_score')} / {cve.get('cvss_severity')}")
    parts.append(f"- Vector: {cve.get('cvss_vector')}")
    parts.append(f"- Attack Vector: {cve.get('attack_vector')}")
    parts.append(f"- CWE: {', '.join(cve.get('cwe_ids') or [])}")
    parts.append(f"- EPSS: {cve.get('epss_score')} (pct {cve.get('epss_percentile')})")
    parts.append(f"- CISA KEV: {bool(cve.get('is_cisa_kev') or False)} (added {cve.get('kev_added_date')})")
    parts.append("")

    # 3) CVE 설명(원문)
    parts.append("## Description (EN)")
    parts.append(_clip(cve.get("description_en") or "", 6000))
    parts.append("")

    # 4) KEV 추가 필드(있으면)
    kev_notes = cve.get("kev_notes")
    kev_action = cve.get("kev_required_action")
    kev_ransom = cve.get("kev_ransomware")
    if kev_notes or kev_action or kev_ransom:
        parts.append("## CISA KEV Context (if any)")
        if kev_ransom is not None:
            parts.append(f"- knownRansomwareCampaignUse: {kev_ransom}")
        if kev_action:
            parts.append("### requiredAction")
            parts.append(_clip(str(kev_action), 2500))
        if kev_notes:
            parts.append("### notes")
            parts.append(_clip(str(kev_notes), 2500))
        parts.append("")

    # 5) 공식 룰 수집 요약(“공식 룰이 있으면 전부 제공”을 근거로 남김)
    parts.append("## Official/Public Rules Discovery Summary")
    if official_rules_summary_lines:
        parts.extend(official_rules_summary_lines[:200])
    else:
        parts.append("- No official/public rules matched in this run.")
    parts.append("")

    # 6) 패치/권고 텍스트(가능하면 무조건)
    parts.append("## Vendor Patch / Advisory (Normalized Text)")
    if not patch_findings:
        parts.append("- No patch/advisory text extracted in this run (JS rendering/auth may be required).")
    else:
        # 너무 길면 누적 상한
        for i, f in enumerate(patch_findings[:4], 1):
            parts.append(f"### Patch Source {i} [{f.kind}] {f.title}")
            parts.append(f"- URL: {f.url}")
            parts.append("")
            parts.append(_clip(f.extracted_text, 6000))
            parts.append("")
    parts.append("")

    # 7) AI 룰 생성 노트(있으면)
    if ai_rule_generation_notes:
        parts.append("## AI Rule Generation Notes")
        parts.append(_clip(ai_rule_generation_notes, 3000))
        parts.append("")

    bundle = _norm("\n".join(parts))

    # 최종 상한 적용
    if len(bundle) > max_total_chars:
        bundle = bundle[:max_total_chars] + "\n...(bundle truncated)"
    return bundle + "\n"
