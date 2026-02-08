import requests
from config import GH_TOKEN

GITHUB_SEARCH = "https://api.github.com/search/code"

def github_search_poc(cve_id: str, max_items=3):
    if not GH_TOKEN:
        return []
    headers = {
        "Authorization": f"Bearer {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
    }
    q = f'"{cve_id}" exploit OR poc OR rce OR metasploit'
    r = requests.get(GITHUB_SEARCH, headers=headers, params={"q": q, "per_page": max_items}, timeout=20)
    if r.status_code != 200:
        return []
    items = r.json().get("items", []) or []
    return [{"repo": it["repository"]["full_name"], "url": it["html_url"]} for it in items[:max_items]]
