import requests

from logger import logger

ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

GAP_KEY = 0.7
GAP_NO_KEY = 8.0

_PROBE_CVE = "CVE-2021-44228"


class NvdKeyError(Exception):
    pass


def gap(api_key: str) -> float:
    return GAP_KEY if api_key else GAP_NO_KEY


def headers(api_key: str) -> dict:
    return {"apiKey": api_key} if api_key else {}


def rejected_key(response) -> bool:
    return (response.status_code == 404
            and "invalid apikey" in str(response.headers.get("message", "")).lower())


def verify(api_key: str) -> None:
    api_key = (api_key or "").strip()
    if not api_key:
        logger.warning(f"NVD_API_KEY 없음 — 요청 간격 {GAP_NO_KEY}초로 진행 "
                       f"(키가 있으면 {GAP_KEY}초)")
        return
    try:
        r = requests.get(ENDPOINT, params={"cveId": _PROBE_CVE},
                         headers=headers(api_key), timeout=45)
    except requests.exceptions.RequestException as e:
        logger.warning(f"NVD 사전 점검을 못 했다(네트워크: {e}) — 키가 유효하다고 보고 진행")
        return
    if rejected_key(r):
        raise NvdKeyError(
            "NVD_API_KEY 가 거부됐다 (Invalid apiKey). "
            "https://nvd.nist.gov/developers/request-an-api-key 에서 재발급해 "
            "리포지토리 시크릿을 갱신하라. "
            "이 상태로 백필을 돌리면 모든 조회가 404 라서 'NVD 에 자료 없음'과 "
            "구별되지 않고, 아무것도 못 채운 채 성공으로 끝난다.")
    if r.status_code != 200:
        logger.warning(f"NVD 사전 점검 응답 {r.status_code} — 키 문제는 아니므로 진행")
        return
    logger.info(f"NVD_API_KEY 유효 · 요청 간격 {GAP_KEY}초")
