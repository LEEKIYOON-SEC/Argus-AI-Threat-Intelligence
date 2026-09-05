import os
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import requests

import nvd
from logger import logger

_SAMPLE = ("CVE-2021-44228", "CVE-2024-3400", "CVE-2023-4966",
           "CVE-2024-1709", "CVE-2022-22965", "CVE-2021-34527")


def main() -> int:
    key = (os.environ.get("NVD_API_KEY") or "").strip()

    logger.info("=" * 60)
    logger.info("NVD API 키 점검")
    logger.info("=" * 60)
    logger.info(f"NVD_API_KEY: {'설정됨 (' + str(len(key)) + '자)' if key else '없음'}")

    try:
        nvd.verify(key)
    except nvd.NvdKeyError as e:
        logger.error(str(e))
        return 1

    if not key:
        logger.warning("키 없이 진행하면 요청당 8초라 재시드 규모(약 1,900건)를 "
                       "60분 작업 안에 못 끝낸다")
        return 0

    logger.info("연속 요청으로 실제 처리율을 잰다 (키가 살아 있으면 30초에 50건 허용)")
    ok = 0
    started = time.time()
    for cve_id in _SAMPLE:
        try:
            r = requests.get(nvd.ENDPOINT, params={"cveId": cve_id},
                             headers=nvd.headers(key), timeout=45)
        except requests.exceptions.RequestException as e:
            logger.warning(f"  {cve_id}: 네트워크 실패 {e}")
            continue
        if nvd.rejected_key(r):
            logger.error(f"  {cve_id}: 키가 거부됐다 — 재발급 필요")
            return 1
        if r.status_code == 429:
            logger.warning(f"  {cve_id}: 429 (한도) — 키는 유효하나 속도 제한에 걸렸다")
            continue
        n = len((r.json() or {}).get("vulnerabilities") or []) if r.status_code == 200 else 0
        logger.info(f"  {cve_id}: HTTP {r.status_code} · 결과 {n}건")
        ok += 1 if n else 0
        time.sleep(nvd.GAP_KEY)

    elapsed = time.time() - started
    logger.info("-" * 60)
    logger.info(f"{ok}/{len(_SAMPLE)}건 정상 조회 · {elapsed:.1f}초")
    if ok == len(_SAMPLE):
        logger.info("키가 살아 있다 — 재시드에 그대로 쓰면 된다")
        return 0
    logger.error("일부 조회가 실패했다 — 위 로그의 상태 코드를 확인하라")
    return 1


if __name__ == "__main__":
    sys.exit(main())
