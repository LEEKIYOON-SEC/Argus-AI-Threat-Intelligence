from utils.http import get_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_cached = None

def load_kev_set():
    global _cached
    if _cached is not None:
        return _cached
    data = get_json(KEV_URL, timeout=60)
    s = set()
    for v in (data.get("vulnerabilities", []) or []):
        cid = v.get("cveID")
        if cid:
            s.add(cid)
    _cached = s
    return _cached

def is_kev(cve_id: str) -> bool:
    return cve_id in load_kev_set()
