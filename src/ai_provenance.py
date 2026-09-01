from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from enrichment_sources import cache_get, cache_put
from logger import logger

_LEDGER_BASE = "https://red.anthropic.com/2026/cvd/data"
_PAYLOAD_URL = f"{_LEDGER_BASE}/payload.json"
_TIMEOUT = 60

_PROGRAMS = (
    ("Google Big Sleep", re.compile(r"\bbig\s?sleep\b", re.I)),
    ("Anthropic / Claude", re.compile(r"\b(?:using|with)\s+claude\b|\bclaude\s+and\s+anthropic\b"
                                      r"|\banthropic\s+research\b", re.I)),
    ("ZeroPath", re.compile(r"\bzeropath\b", re.I)),
    ("XBOW", re.compile(r"\bxbow\b", re.I)),
    ("Google CodeMender", re.compile(r"\bcodemender\b", re.I)),
    ("DARPA AIxCC", re.compile(r"\baixcc\b", re.I)),
)


@dataclass(frozen=True)
class Provenance:
    program: str
    detail: str
    url: str = ""

    def as_state(self) -> Dict:
        return {"ai_discovered": True, "ai_program": self.program,
                "ai_detail": self.detail[:300], "ai_url": self.url}


def load_anthropic_ledger(ttl_hours: int = 6) -> Optional[Dict[str, Dict]]:
    raw = cache_get("anthropic-cvd.json", ttl_hours=ttl_hours)
    if raw is None:
        try:
            resp = requests.get(_PAYLOAD_URL, timeout=_TIMEOUT,
                                headers={"User-Agent": "argus-provenance"})
            resp.raise_for_status()
            if "json" not in (resp.headers.get("Content-Type") or "").lower():
                logger.warning("Anthropic 레저: JSON이 아닌 응답 — 경로 변경 가능성")
                return None
            raw = resp.content
            cache_put("anthropic-cvd.json", raw)
            logger.info(f"📥 Anthropic 공개 레저 수신 ({len(raw) / 1024 / 1024:.1f}MB)")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Anthropic 레저 수신 실패: {e}")
            return None
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except ValueError as e:
        logger.warning(f"Anthropic 레저 파싱 실패: {e}")
        return None

    out: Dict[str, Dict] = {}
    for rec in data.get("cve_records") or []:
        cve_id = str(rec.get("identifier") or "").upper()
        if not cve_id.startswith("CVE-"):
            continue
        findings = rec.get("findings") or []
        first = findings[0] if findings else {}
        out[cve_id] = {
            "ant_id": first.get("ant_id", ""),
            "project": first.get("project", ""),
            "bug_class": first.get("bug_class", ""),
            "severity": first.get("severity", ""),
            "title": first.get("title", ""),
            "revealed_at": rec.get("revealed_at", ""),
            "count": len(findings),
        }
    logger.info(f"  ✅ Anthropic CVD: CVE {len(out)}건 (출처: red.anthropic.com)")
    return out


def anthropic_provenance(cve_id: str, ledger: Optional[Dict[str, Dict]]) -> Optional[Provenance]:
    entry = (ledger or {}).get(cve_id.upper())
    if not entry:
        return None
    bits = [b for b in (entry.get("ant_id"), entry.get("project"),
                        entry.get("bug_class")) if b]
    return Provenance(
        program="Anthropic CVD",
        detail=" · ".join(bits) or entry.get("title", ""),
        url="https://red.anthropic.com/2026/cvd/ledger/",
    )


def credit_provenance(credits: Optional[List[str]]) -> Optional[Provenance]:
    for text in credits or []:
        s = str(text or "")
        if not s:
            continue
        for program, pattern in _PROGRAMS:
            if pattern.search(s):
                return Provenance(program=program, detail=s.strip())
    return None


def detect(cve_id: str, credits: Optional[List[str]],
           ledger: Optional[Dict[str, Dict]] = None) -> Optional[Provenance]:
    return anthropic_provenance(cve_id, ledger) or credit_provenance(credits)
