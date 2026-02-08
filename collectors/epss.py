from utils.http import get_json

EPSS_API = "https://api.first.org/data/v1/epss"

def get_epss(cve_id: str) -> float:
    data = get_json(EPSS_API, params={"cve": cve_id}, timeout=20)
    rows = data.get("data", []) or []
    if not rows:
        return 0.0
    return float(rows[0].get("epss", 0.0))
