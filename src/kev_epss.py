from __future__ import annotations

import logging
from datetime import datetime
from typing import Dict, List, Optional

from .http import http_get_json

log = logging.getLogger("argus.kev_epss")

# EPSS API base: https://api.first.org/data/v1/epss :contentReference[oaicite:8]{index=8}
EPSS_API = "https://api.first.org/data/v1/epss"

# CISA KEV JSON feed (widely referenced as default API URL) :contentReference[oaicite:9]{index=9}
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _chunk(lst: list[str], n: int) -> list[list[str]]:
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def fetch_kev_index() -> dict[str, dict]:
    """
    KEV 전체를 받아 cveID -> entry 로 인덱싱.
    """
    j = http_get_json(CISA_KEV_JSON, timeout=60)
    vulns = j.get("vulnerabilities") or []
    idx: dict[str, dict] = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve_id = v.get("cveID") or v.get("cveId") or v.get("cve")
        if isinstance(cve_id, str) and cve_id.startswith("CVE-"):
            idx[cve_id.upper()] = v
    return idx


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, dict]:
    """
    EPSS API는 cve 파라미터로 배치 조회 가능. :contentReference[oaicite:10]{index=10}
    - 반환: cve_id -> {"epss": float, "percentile": float, "date": "..."}
    """
    out: dict[str, dict] = {}
    # FIRST 문서 예시상 100개 단위가 무난(보수적으로 100)
    for part in _chunk([c.upper() for c in cve_ids], 100):
        q = ",".join(part)
        url = f"{EPSS_API}?cve={q}"
        j = http_get_json(url, timeout=60)
        data = j.get("data") or []
        for row in data:
            if not isinstance(row, dict):
                continue
            cid = (row.get("cve") or "").upper()
            if not cid.startswith("CVE-"):
                continue
            try:
                epss = float(row.get("epss")) if row.get("epss") is not None else None
            except Exception:
                epss = None
            try:
                pct = float(row.get("percentile")) if row.get("percentile") is not None else None
            except Exception:
                pct = None
            out[cid] = {
                "epss": epss,
                "percentile": pct,
                "date": row.get("date"),
            }
    return out


def enrich_with_kev_epss(cfg, cves: list[dict]) -> list[dict]:
    """
    입력: cve dict list
    출력: 같은 list(각 cve dict에 is_cisa_kev, kev_added_date, epss_score, epss_percentile 추가)
    """
    if not cves:
        return cves

    ids = [c["cve_id"] for c in cves if c.get("cve_id")]
    kev_idx = fetch_kev_index()
    epss_idx = fetch_epss_scores(ids)

    for c in cves:
        cid = c["cve_id"].upper()

        kev_entry = kev_idx.get(cid)
        if kev_entry:
            c["is_cisa_kev"] = True
            # KEV entry에는 dateAdded(YYYY-MM-DD)가 일반적으로 존재
            c["kev_added_date"] = kev_entry.get("dateAdded") or kev_entry.get("date_added")
            # evidence로 유용한 필드들을 저장(LLM evidence bundle에도 활용)
            c["kev_ransomware"] = kev_entry.get("knownRansomwareCampaignUse")
            c["kev_required_action"] = kev_entry.get("requiredAction")
            c["kev_notes"] = kev_entry.get("notes")
        else:
            c["is_cisa_kev"] = False
            c["kev_added_date"] = None

        epss = epss_idx.get(cid)
        if epss:
            c["epss_score"] = epss.get("epss")
            c["epss_percentile"] = epss.get("percentile")
            c["epss_date"] = epss.get("date")
        else:
            c["epss_score"] = None
            c["epss_percentile"] = None
            c["epss_date"] = None

    return cves
