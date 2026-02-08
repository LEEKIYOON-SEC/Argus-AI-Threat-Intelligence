from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .http import http_get_json, HttpError

log = logging.getLogger("argus.cve_sources")

# NVD v2.0 CVE API (목록/시간필터용)
# docs: https://nvd.nist.gov/developers/vulnerabilities :contentReference[oaicite:4]{index=4}
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVE.org 공개 레코드(상세용; CVE JSON 5.0)
# 예: https://cveawg.mitre.org/api/cve/CVE-2024-21672 :contentReference[oaicite:5]{index=5}
CVEORG_PUBLIC_API = "https://cveawg.mitre.org/api/cve"


def _iso_z(dt: datetime) -> str:
    """
    NVD는 pubStartDate/pubEndDate에 ISO8601(UTC Z)을 사용.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _safe_get(d: dict, path: list[str], default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def _normalize_from_cveorg(cveorg_json: dict) -> Optional[dict]:
    """
    cveawg.mitre.org/api/cve/<CVE-ID> 응답을 '내부 표준 dict'로 변환.
    목표 필드:
      - cve_id
      - published_date / last_modified_date
      - description_en (원문) + (추후 LLM로 한글화)
      - cvss_score / cvss_severity / cvss_vector / attack_vector
      - cwe_ids
      - references
      - vendor/product/version 정보는 이후 단계에서 확장
    """
    cve_id = cveorg_json.get("cveMetadata", {}).get("cveId")
    if not cve_id:
        return None

    # REJECTED 제외 (요구사항)
    # CVE JSON 5.0에서 state가 "REJECTED"로 들어갈 수 있음.
    state = cveorg_json.get("cveMetadata", {}).get("state")
    if state and str(state).upper() == "REJECTED":
        return None

    date_published = cveorg_json.get("cveMetadata", {}).get("datePublished")
    date_updated = cveorg_json.get("cveMetadata", {}).get("dateUpdated")

    # published_date는 date만 저장(정리정책)
    pub_date_only = None
    mod_date_only = None
    try:
        if isinstance(date_published, str) and len(date_published) >= 10:
            pub_date_only = date_published[:10]
        if isinstance(date_updated, str) and len(date_updated) >= 10:
            mod_date_only = date_updated[:10]
    except Exception:
        pass

    # 영어 설명 추출(원문 유지)
    descs = _safe_get(cveorg_json, ["containers", "cna", "descriptions"], default=[]) or []
    desc_en = None
    for d in descs:
        if isinstance(d, dict) and d.get("lang") == "en":
            desc_en = d.get("value")
            break
    if not desc_en and descs:
        # fallback: 첫번째
        v = descs[0].get("value") if isinstance(descs[0], dict) else None
        desc_en = v

    # references
    refs = _safe_get(cveorg_json, ["containers", "cna", "references"], default=[]) or []
    ref_urls: list[str] = []
    for r in refs:
        if isinstance(r, dict) and r.get("url"):
            ref_urls.append(r["url"])

    # problemTypes → CWE
    cwe_ids: list[str] = []
    ptypes = _safe_get(cveorg_json, ["containers", "cna", "problemTypes"], default=[]) or []
    for pt in ptypes:
        desc_list = pt.get("descriptions") if isinstance(pt, dict) else None
        if not isinstance(desc_list, list):
            continue
        for it in desc_list:
            # commonly: {"lang":"en","description":"CWE-79"}
            if isinstance(it, dict):
                val = it.get("description") or it.get("value")
                if isinstance(val, str) and val.upper().startswith("CWE-"):
                    cwe_ids.append(val.upper())
    cwe_ids = sorted(list(set(cwe_ids)))

    # CVSS: CNA metrics 내 cvssV3_1 / cvssV4_0 등이 있을 수 있음
    # 여기서는 "가장 신뢰 가능한/존재하는 baseScore" 하나를 택하고,
    # 추후 확장에서 'ADP vs CNA' 출처별 비교를 구현.
    cvss_score = None
    cvss_sev = None
    cvss_vec = None
    attack_vector = None

    metrics = _safe_get(cveorg_json, ["containers", "cna", "metrics"], default=[]) or []
    for m in metrics:
        if not isinstance(m, dict):
            continue
        # cvssV3_1
        v31 = m.get("cvssV3_1")
        if isinstance(v31, dict):
            cvss_score = v31.get("baseScore", cvss_score)
            cvss_sev = v31.get("baseSeverity", cvss_sev)
            cvss_vec = v31.get("vectorString", cvss_vec)
            attack_vector = v31.get("attackVector", attack_vector)
            break
        # cvssV3_0
        v30 = m.get("cvssV3_0")
        if isinstance(v30, dict):
            cvss_score = v30.get("baseScore", cvss_score)
            cvss_sev = v30.get("baseSeverity", cvss_sev)
            cvss_vec = v30.get("vectorString", cvss_vec)
            attack_vector = v30.get("attackVector", attack_vector)
            break
        # cvssV4_0 (있으면 확장)
        v40 = m.get("cvssV4_0")
        if isinstance(v40, dict):
            # v4의 필드는 다를 수 있어 보수적으로 처리
            cvss_score = v40.get("baseScore", cvss_score)
            cvss_sev = v40.get("baseSeverity", cvss_sev)
            cvss_vec = v40.get("vectorString", cvss_vec)
            # attack vector는 v4에서 다른 경로일 수 있어 여기선 보류
            break

    out = {
        "cve_id": cve_id,
        "source": "cve.org",
        "date_published": date_published,
        "date_updated": date_updated,
        "published_date": pub_date_only,
        "last_modified_date": mod_date_only,
        "description_en": desc_en or "",
        "references": ref_urls,
        "cwe_ids": cwe_ids,
        "cce_ids": [],  # 추후 확장(대개 NVD/CPE 쪽에서 파생)
        "cvss_score": float(cvss_score) if cvss_score is not None else None,
        "cvss_severity": (str(cvss_sev).upper() if cvss_sev else None),
        "cvss_vector": cvss_vec,
        "attack_vector": (str(attack_vector).upper() if attack_vector else None),
    }
    return out


def fetch_cveorg_record(cve_id: str) -> Optional[dict]:
    """
    CVE.org 공개 API에서 단일 CVE 레코드를 가져와 표준화.
    """
    url = f"{CVEORG_PUBLIC_API}/{cve_id}"
    try:
        j = http_get_json(url, timeout=60)
    except Exception as e:
        log.warning("cve.org fetch failed for %s: %s", cve_id, e)
        return None
    return _normalize_from_cveorg(j)


def fetch_new_cves_since(since: datetime, until: Optional[datetime] = None, max_pages: int = 10) -> List[str]:
    """
    NVD를 사용해 'published' 시간 필터로 CVE ID 리스트를 수집.
    - 주 목적: 신규 CVE ID 디스커버리
    - 상세정보는 이후 cve.org에서 가져옴

    NVD API docs: :contentReference[oaicite:6]{index=6}
    """
    if until is None:
        until = datetime.now(timezone.utc)

    pub_start = _iso_z(since)
    pub_end = _iso_z(until)

    cve_ids: list[str] = []
    start_index = 0
    results_per_page = 2000  # NVD는 offset 기반 pagination
    page = 0

    while page < max_pages:
        page += 1
        url = (
            f"{NVD_CVE_API}"
            f"?pubStartDate={pub_start}"
            f"&pubEndDate={pub_end}"
            f"&startIndex={start_index}"
            f"&resultsPerPage={results_per_page}"
        )

        try:
            j = http_get_json(url, timeout=60)
        except HttpError as e:
            log.error("NVD list failed: %s", e)
            break
        except Exception as e:
            log.error("NVD list error: %s", e)
            break

        vulns = j.get("vulnerabilities") or []
        if not isinstance(vulns, list) or not vulns:
            break

        for item in vulns:
            cve = (item or {}).get("cve") if isinstance(item, dict) else None
            cve_id = (cve or {}).get("id") if isinstance(cve, dict) else None
            if not cve_id:
                continue
            # NVD에도 REJECTED/분류가 있을 수 있어 1차로 걸러주되,
            # 최종 필터는 cve.org state 기준으로 한다.
            status = (cve or {}).get("vulnStatus")
            if status and str(status).upper() == "REJECTED":
                continue
            cve_ids.append(cve_id)

        # pagination
        total = j.get("totalResults")
        if isinstance(total, int):
            start_index += results_per_page
            if start_index >= total:
                break
        else:
            # totalResults가 없으면 보수적으로 1페이지만
            break

    # 중복 제거/정렬(시간순은 깨질 수 있지만, 이후 per-CVE 처리에서 무관)
    return sorted(list(set(cve_ids)))


def fetch_cveorg_published_since(since: datetime, until: Optional[datetime] = None) -> List[dict]:
    """
    최종적으로 사용할 'CVE 리스트(dict)'를 반환.
    - NVD로 신규 CVE IDs를 뽑고,
    - cve.org 공개 API로 상세를 받아,
    - REJECTED 제외 + datePublished 존재(= PUBLISHED로 간주)만 남김.
    """
    ids = fetch_new_cves_since(since, until=until)

    out: list[dict] = []
    for cve_id in ids:
        rec = fetch_cveorg_record(cve_id)
        if not rec:
            continue

        # PUBLISHED만 사용: datePublished 없으면 제외
        # (CVE JSON 5.0에서 datePublished가 없을 수 있다는 사례 존재) :contentReference[oaicite:7]{index=7}
        if not rec.get("date_published"):
            continue

        out.append(rec)

    log.info("CVE.org PUBLISHED count=%d (since=%s)", len(out), since.isoformat())
    return out
