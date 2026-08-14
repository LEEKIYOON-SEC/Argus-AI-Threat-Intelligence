"""CVE ↔ 패키지 역인덱스 생성 — 주 1회 별도 실행.

대시보드가 사용자의 SBOM(sbom-list.csv)과 대조할 때 쓰는 사전을 만든다. 대조 자체는
브라우저에서 일어나므로 자산 정보는 이 파이프라인에 들어오지 않는다.

매시간 파이프라인과 분리한 이유: OSV 덤프가 합계 ~900MB라 내려받고 훑는 데 몇 분이
걸린다. 취약점↔패키지 매핑은 시간 단위로 바뀌지 않으므로 주 1회면 충분하고, 무엇보다
매시간 실행의 시간 예산(38분)을 잠식하면 안 된다.
"""
import json
import os
import sys

import osv_index
from database import ArgusDB
from logger import logger

_OUT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs", "data", "cve-packages.json"
)
_CVES = os.path.join(os.path.dirname(_OUT), "cves.json")


def _tracked_cve_ids() -> list:
    """대시보드에 노출 중인 CVE 목록. export가 만든 cves.json을 우선 쓰고,
    없으면 DB에서 직접 읽는다(워크플로 순서에 의존하지 않게)."""
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
        db = ArgusDB()
        rows = db.get_rows_missing_published(limit=50000)  # id만 필요 — 추적 행 전량
        ids = [r["id"] for r in rows if r.get("id")]
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

    index = osv_index.build_index(ids)
    if not index:
        logger.warning("매칭된 패키지가 없습니다 — 기존 파일을 덮어쓰지 않고 종료")
        return 1

    return 0 if osv_index.write_index(index, _OUT) else 1


if __name__ == "__main__":
    sys.exit(main())
