from utils.http import get_json
from utils.time import utc_minutes_ago, utc_iso
from config import DISCOVERY_LOOKBACK_MINUTES

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def discover_recent_cves(max_results=200):
    start = utc_minutes_ago(DISCOVERY_LOOKBACK_MINUTES)
    params = {
        "lastModStartDate": utc_iso(start),
        "lastModEndDate": utc_iso(utc_minutes_ago(0)),
        "resultsPerPage": min(max_results, 2000),
        "startIndex": 0,
    }
    data = get_json(NVD_BASE, params=params, timeout=60)
    vulns = data.get("vulnerabilities", [])
    cve_ids = []
    for v in vulns:
        c = v.get("cve", {})
        cve_id = c.get("id")
        if cve_id:
            cve_ids.append(cve_id)
    return list(dict.fromkeys(cve_ids))
