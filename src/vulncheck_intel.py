from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger("argus.vulncheck")


@dataclass
class VulnCheckFinding:
    cve_id: str
    kind: str               # "weaponized" | "exploit" | "poc" | "advisory" | "other"
    title: str
    summary: str
    evidence: str           # 핵심 근거 텍스트(LLM 입력용)
    source: str             # "VulnCheck"
    raw: dict


def _headers(api_key: str) -> dict:
    # VulnCheck API는 키 기반 인증을 제공(구체적인 헤더명은 환경에 따라 다를 수 있어 보수적으로 지원)
    # - 흔히 Authorization: Bearer <key> 또는 X-Api-Key 형태가 사용됨
    return {
        "Authorization": f"Bearer {api_key}",
        "X-Api-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
    }


def _clip(s: str, n: int) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n] + "…(truncated)"


def fetch_vulncheck_findings(cfg, cve_id: str, timeout: int = 35) -> List[VulnCheckFinding]:
    """
    VulnCheck를 이용해 "실제 악용/무기화 가능성" 근거를 텍스트로 확보.
    - API 스키마는 플랜/버전에 따라 달라질 수 있으므로,
      여기서는 '안전한 best-effort'로 구현(성공하면 근거 텍스트화, 실패하면 빈 리스트).
    - 비용 0 조건: 사용자 키가 이미 있고 무료/체험 범위 내에서만 사용.
    """
    api_key = getattr(cfg, "VULNCHECK_API_KEY", None)
    if not api_key:
        return []

    cve_id = cve_id.upper().strip()

    # 가장 보수적으로 "CVE 검색" endpoint를 추정.
    # 환경에 따라 경로가 다를 수 있어, cfg.VULNCHECK_BASE_URL로 오버라이드 가능.
    base = getattr(cfg, "VULNCHECK_BASE_URL", "https://api.vulncheck.com/v3").rstrip("/")
    url = f"{base}/cves/{cve_id}"

    try:
        r = requests.get(url, headers=_headers(api_key), timeout=timeout)
        if r.status_code >= 400:
            log.info("VulnCheck fetch failed %s %s", r.status_code, r.text[:200])
            return []
        j = r.json()
    except Exception as e:
        log.info("VulnCheck request error: %s", e)
        return []

    findings: List[VulnCheckFinding] = []

    # 스키마가 불확실하므로 가능한 필드들을 폭넓게 수용
    # 기대: weaponized/epss-like/exploit references/known exploits 등이 있을 수 있음.
    raw = j if isinstance(j, dict) else {"data": j}

    title = raw.get("title") or raw.get("cve") or cve_id
    summary = raw.get("summary") or raw.get("description") or ""

    # exploit/weaponized 표시 추정
    weaponized = raw.get("weaponized") or raw.get("isWeaponized") or raw.get("exploited") or False
    kind = "weaponized" if weaponized else "other"

    # 근거 텍스트 구성(LLM 입력용)
    evidence_lines: List[str] = []
    evidence_lines.append(f"- VulnCheck CVE record: {cve_id}")
    if summary:
        evidence_lines.append(f"- Summary: {_clip(summary, 1500)}")

    # exploit references 가능 필드들
    for key in ["exploits", "pocs", "references", "links", "sources"]:
        val = raw.get(key)
        if isinstance(val, list) and val:
            evidence_lines.append(f"- {key}:")
            for it in val[:20]:
                if isinstance(it, str):
                    evidence_lines.append(f"  - {it}")
                elif isinstance(it, dict):
                    # dict에서 title/url/type 등을 텍스트화
                    t = it.get("title") or it.get("name") or it.get("type") or "item"
                    u = it.get("url") or it.get("link") or ""
                    evidence_lines.append(f"  - {t} {u}".strip())
            break

    evidence = "\n".join(evidence_lines).strip()

    findings.append(
        VulnCheckFinding(
            cve_id=cve_id,
            kind=kind,
            title=str(title),
            summary=_clip(summary, 2000),
            evidence=evidence,
            source="VulnCheck",
            raw=raw,
        )
    )
    return findings


def build_vulncheck_section_text(findings: List[VulnCheckFinding]) -> str:
    """
    Evidence Bundle에 삽입할 '정규화 텍스트' 섹션.
    """
    if not findings:
        return "## VulnCheck (OSINT/Exploit Intel)\n- No VulnCheck findings in this run.\n"

    lines: List[str] = []
    lines.append("## VulnCheck (OSINT/Exploit Intel)")
    for f in findings[:3]:
        lines.append(f"- Kind: {f.kind}")
        lines.append(f"- Title: {f.title}")
        if f.summary:
            lines.append(f"- Summary: {f.summary}")
        lines.append("- Evidence:")
        lines.append(f.evidence)
        lines.append("")
    return "\n".join(lines).strip() + "\n"
