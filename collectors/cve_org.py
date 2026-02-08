from utils.http import get_json
from utils.text import compact_whitespace

CVE_AWG = "https://cveawg.mitre.org/api/cve/"

def fetch_cve_record(cve_id: str):
    data = get_json(f"{CVE_AWG}{cve_id}", timeout=30)

    meta = data.get("cveMetadata", {})
    state = meta.get("state")
    if state != "PUBLISHED":
        return None

    containers = data.get("containers", {})
    cna = containers.get("cna", {}) or {}
    adp_list = containers.get("adp", []) or []

    title = cna.get("title") or ""
    desc_en = ""
    descs = cna.get("descriptions", []) or []
    for d in descs:
        if d.get("lang") == "en":
            desc_en = d.get("value") or ""
            break
    desc_en = compact_whitespace(desc_en)

    refs = []
    for r in (cna.get("references", []) or []):
        u = r.get("url")
        if u:
            refs.append(u)

    cwe = None
    ptypes = cna.get("problemTypes", []) or []
    if ptypes:
        descs2 = (ptypes[0].get("descriptions", []) or [])
        if descs2:
            cwe = descs2[0].get("cweId") or descs2[0].get("description")

    def extract_cvss(container_obj):
        metrics = container_obj.get("metrics", []) or []
        for m in metrics:
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if k in m:
                    x = m[k]
                    return {
                        "cvss_version": x.get("version") or k.replace("cvssV", "").replace("_", "."),
                        "cvss_score": x.get("baseScore"),
                        "cvss_vector": x.get("vectorString"),
                        "severity": x.get("baseSeverity"),
                        "attackVector": x.get("attackVector"),
                    }
        return None

    cvss = extract_cvss(cna) or {}
    adp_cvss = None
    adp_sev = None
    for adp in adp_list:
        cv = extract_cvss(adp)
        if cv and cv.get("cvss_score") is not None:
            adp_cvss = cv.get("cvss_score")
            adp_sev = cv.get("severity")
            if cvss.get("cvss_score") is None:
                cvss = cv
            break

    return {
        "cve_id": cve_id,
        "published_date": meta.get("datePublished"),
        "last_modified": meta.get("dateUpdated"),
        "source": "CVE",
        "title": title,
        "description_en": desc_en,
        "references": refs,
        "cwe": cwe,
        "cvss_version": cvss.get("cvss_version"),
        "cvss_score": cvss.get("cvss_score"),
        "cvss_vector": cvss.get("cvss_vector"),
        "severity": cvss.get("severity"),
        "attackVector": cvss.get("attackVector"),
        "adp_cvss_score": adp_cvss,
        "adp_severity": adp_sev,
    }
