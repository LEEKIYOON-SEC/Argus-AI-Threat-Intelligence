ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

GAP_KEY = 0.7
GAP_NO_KEY = 8.0


def gap(api_key: str) -> float:
    return GAP_KEY if api_key else GAP_NO_KEY


def headers(api_key: str) -> dict:
    return {"apiKey": api_key} if api_key else {}
