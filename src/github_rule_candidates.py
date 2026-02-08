from __future__ import annotations

import os
import re
from typing import Dict, List

from .github_osint import GitHubFinding
from .rule_validation import validate_by_engine
from .settings_store import get_trusted_github_repos


def _default_allowlist() -> List[str]:
    return [
        "SigmaHQ/sigma",
        "Neo23x0/sigma",
        "Neo23x0/signature-base",
        "Yara-Rules/rules",
        "OISF/suricata",
    ]


def _get_allowlist(cfg) -> List[str]:
    # 1) Supabase DB allowlist (웹 UI)
    db_repos = get_trusted_github_repos(cfg)
    if db_repos:
        return [x.repo_full_name for x in db_repos]

    # 2) env allowlist
    raw = getattr(cfg, "GITHUB_TRUSTED_REPOS", None) or os.getenv("GITHUB_TRUSTED_REPOS", "")
    raw = (raw or "").strip()
    if raw:
        return [x.strip() for x in raw.split(",") if x.strip()]

    # 3) default
    return _default_allowlist()


def _extract_repo_full_name_from_title(title: str) -> str:
    if not title:
        return ""
    parts = title.split("/")
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return ""


def _is_sigma_path(path: str) -> bool:
    p = (path or "").lower()
    return p.endswith((".yml", ".yaml")) and ("sigma" in p or "/rules/" in p or "/detections/" in p or "/detection/" in p)


def _is_yara_path(path: str) -> bool:
    p = (path or "").lower()
    return p.endswith((".yar", ".yara"))


def _is_rules_path(path: str) -> bool:
    p = (path or "").lower()
    return p.endswith(".rules")


def _extract_snippet_block(evidence: str) -> str:
    if not evidence:
        return ""
    m = re.search(r"```(?:\w+)?\n(.*?)\n```", evidence, flags=re.DOTALL)
    if not m:
        return ""
    return (m.group(1) or "").strip()


def _decide_engine_with_validation(path: str, rule_text: str) -> str:
    p = (path or "").lower()

    if _is_sigma_path(path):
        return "sigma" if validate_by_engine("sigma", rule_text).ok else ""
    if _is_yara_path(path):
        return "yara" if validate_by_engine("yara", rule_text).ok else ""

    if _is_rules_path(path):
        if "snort3" in p or "/snort3/" in p:
            preferred = ["snort3", "snort2", "suricata"]
        elif "snort" in p or "/snort/" in p:
            preferred = ["snort2", "suricata", "snort3"]
        elif "suricata" in p or "/suricata/" in p:
            preferred = ["suricata", "snort2", "snort3"]
        else:
            preferred = ["suricata", "snort2", "snort3"]

        for eng in preferred:
            if validate_by_engine(eng, rule_text).ok:
                return eng
        return ""

    return ""


def fetch_trusted_github_rule_candidates(
    cfg,
    *,
    cve_id: str,
    github_findings: List[GitHubFinding],
    max_rules: int = 4,
) -> List[Dict]:
    allow = set([x.lower() for x in _get_allowlist(cfg)])
    out: List[Dict] = []

    for f in github_findings:
        if f.kind != "code":
            continue

        repo = _extract_repo_full_name_from_title(f.title).lower()
        if not repo or repo not in allow:
            continue

        snippet = _extract_snippet_block(f.evidence)
        if not snippet:
            continue

        engine = _decide_engine_with_validation(f.title, snippet)
        if not engine:
            continue

        out.append(
            {
                "engine": engine,
                "source": "github_trusted",
                "rule_path": f.title,
                "rule_text": snippet,
                "reference": f.raw_url or f.api_url or "",
            }
        )
        if len(out) >= max_rules:
            break

    return out
