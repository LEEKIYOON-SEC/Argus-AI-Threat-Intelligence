import json
import os
import sys

import osv_index
from database import ArgusDB
from logger import logger

_DATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs", "data"
)
_OUT = os.path.join(_DATA, "cve-packages.json")
_MAL_OUT = os.path.join(_DATA, "malicious-packages.json")
_CVES = os.path.join(_DATA, "cves.json")


def _tracked_cve_ids() -> list:
    try:
        with open(_CVES, encoding="utf-8") as f:
            rows = json.load(f)
        ids = [r["id"] for r in rows if r.get("id")]
        if ids:
            logger.info(f"대상 CVE {len(ids):,}건 (cves.json)")
            return ids
    except (OSError, ValueError, KeyError):
        pass

    try:
        ids = ArgusDB().get_tracked_ids()
        logger.info(f"대상 CVE {len(ids):,}건 (DB)")
        return ids
    except Exception as e:
        logger.error(f"대상 CVE 조회 실패: {e}")
        return []


def main() -> int:
    logger.info("=" * 60)
    logger.info("CVE ↔ 패키지 역인덱스 생성")
    logger.info("=" * 60)

    ids = _tracked_cve_ids()
    if not ids:
        logger.error("대상 CVE가 없어 중단합니다")
        return 1

    index, kernel_aliases = osv_index.build_index(ids)
    if not index:
        logger.warning("매칭된 패키지가 없습니다 — 기존 파일을 덮어쓰지 않고 종료")
        return 1
    ok = osv_index.write_index(index, _OUT, kernel_aliases=kernel_aliases)

    logger.info("─" * 60)
    mal = osv_index.build_malicious_index()
    if mal:
        osv_index.write_malicious(mal, _MAL_OUT)
    else:
        logger.warning("악성 패키지 목록이 비어 있습니다 — 기존 파일 유지")

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
