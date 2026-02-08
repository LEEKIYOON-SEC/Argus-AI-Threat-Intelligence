from utils.http import get_json
from config import VULNCHECK_API_KEY

def is_weaponized_vulncheck(cve_id: str) -> bool:
    if not VULNCHECK_API_KEY:
        return False
    url = "https://api.vulncheck.com/v3/index/vulncheck-kev"
    headers = {"Authorization": f"Bearer {VULNCHECK_API_KEY}"}
    try:
        data = get_json(url, params={"cve": cve_id}, headers=headers, timeout=30)
        return bool(data.get("data"))
    except Exception:
        return False
