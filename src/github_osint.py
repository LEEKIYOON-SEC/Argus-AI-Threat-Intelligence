from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

import requests

log = logging.getLogger("argus.github_osint")


@dataclass
class GitHubFinding:
    cve_id: str
    kind: str        # "repo" | "code"
    title: str
    summary: str
    evidence: str    # LLM 입력용 정규화 텍스트
    raw_url: str     # URL은 참고용(LLM에는 URL만 던지지 않음)


def _clip(s: str, n: int) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n] + "…(truncated)"


def _headers(token: str) -> dict:
    # GitHub REST API 인증
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
    }


def search_repos_by_cve(cfg, cve_id: str, max_items: int = 5) -> List[GitHubFinding]:
    """
    GitHub repo 검색(비용 0) — PoC/Exploit/Rule 관련 리포지토리 힌트 확보.
    """
    token = getattr(cfg, "GH_TOKEN", None)
    if not token:
        return []

    cve_id = cve_id.upper().strip()
    q = f'"{cve_id}" exploit OR poc OR proof-of-concept OR yara OR sigma OR snort OR suricata'
    url = "https://api.github.com/search/repositories"

    try:
        r = requests.get(url, headers=_headers(token), params={"q": q, "sort": "updated", "order": "desc"}, timeout=25)
        if r.status_code >= 400:
            log.info("GitHub repo search failed %s %s", r.status_code, r.text[:200])
            return []
        j = r.json()
    except Exception as e:
        log.info("GitHub repo search error: %s", e)
        return []

    items = j.get("items") or []
    out: List[GitHubFinding] = []

    for it in items[:max_items]:
        full = it.get("full_name") or it.get("name") or "repo"
        desc = it.get("description") or ""
        html = it.get("html_url") or ""
        evidence = "\n".join(
            [
                f"- Repository: {full}",
                f"- Description: {_clip(desc, 500)}",
                f"- Stars: {it.get('stargazers_count')}",
                f"- Updated: {it.get('updated_at')}",
                f"- Topics: {', '.join(it.get('topics') or [])}",
                f"- URL: {html}",
            ]
        ).strip()

        out.append(
            GitHubFinding(
                cve_id=cve_id,
                kind="repo",
                title=str(full),
                summary=_clip(desc, 700),
                evidence=evidence,
                raw_url=html,
            )
        )

    return out


def search_code_by_cve(cfg, cve_id: str, max_items: int = 5) -> List[GitHubFinding]:
    """
    GitHub code search — CVE 언급 파일/룰 파일 경로를 텍스트로 확보.
    NOTE: Code Search API는 결과 제한/레이트 제한이 있으므로 max_items 작게.
    """
    token = getattr(cfg, "GH_TOKEN", None)
    if not token:
        return []

    cve_id = cve_id.upper().strip()
    q = f'"{cve_id}" (path:rules OR extension:rules OR extension:yml OR extension:yaml OR extension:yar OR extension:yara OR extension:lua)'
    url = "https://api.github.com/search/code"

    try:
        r = requests.get(url, headers=_headers(token), params={"q": q, "sort": "indexed", "order": "desc"}, timeout=25)
        if r.status_code >= 400:
            log.info("GitHub code search failed %s %s", r.status_code, r.text[:200])
            return []
        j = r.json()
    except Exception as e:
        log.info("GitHub code search error: %s", e)
        return []

    items = j.get("items") or []
    out: List[GitHubFinding] = []

    for it in items[:max_items]:
        name = it.get("name") or "file"
        path = it.get("path") or ""
        repo = (it.get("repository") or {}).get("full_name") or "repo"
        html = it.get("html_url") or ""

        evidence = "\n".join(
            [
                f"- Repository: {repo}",
                f"- File: {path}",
                f"- Name: {name}",
                f"- URL: {html}",
                "- NOTE: This is a discovery hint. For LLM input, fetch & normalize the relevant file content in a later step if needed.",
            ]
        ).strip()

        out.append(
            GitHubFinding(
                cve_id=cve_id,
                kind="code",
                title=f"{repo}/{path}",
                summary=f"{repo}/{path}",
                evidence=evidence,
                raw_url=html,
            )
        )

    return out


def build_github_section_text(findings: List[GitHubFinding]) -> str:
    if not findings:
        return "## GitHub OSINT (Discovery)\n- No GitHub findings in this run (or GH_TOKEN not set).\n"

    lines: List[str] = []
    lines.append("## GitHub OSINT (Discovery)")
    for f in findings[:10]:
        lines.append(f"- Kind: {f.kind} / Title: {f.title}")
        if f.summary:
            lines.append(f"  - Summary: {f.summary}")
        lines.append("  - Evidence:")
        for ln in f.evidence.splitlines():
            lines.append("    " + ln)
        lines.append("")
    return "\n".join(lines).strip() + "\n"
