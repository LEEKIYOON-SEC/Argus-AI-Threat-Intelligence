import os
import sys
import time
from typing import Dict, List

import requests

from collector import affected_from_cpes
from database import ArgusDB
from logger import logger

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_GAP_NO_KEY, _GAP_KEY = 8.0, 0.7


def _fetch_cpe(cve_id: str, api_key: str, existing: List[Dict] = None) -> List[Dict]:
    headers = {"apiKey": api_key} if api_key else {}
    try:
        r = requests.get(_NVD, params={"cveId": cve_id}, headers=headers, timeout=60)
        r.raise_for_status()
        vulns = (r.json() or {}).get("vulnerabilities") or []
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.warning(f"  {cve_id} NVD 조회 실패: {e}")
        return []
    if not vulns:
        return []

    cpes = [m.get("criteria", "")
            for conf in (vulns[0].get("cve") or {}).get("configurations") or []
            for node in conf.get("nodes") or []
            for m in node.get("cpeMatch") or []]
    return affected_from_cpes(cpes, existing)


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "")
    limit = int(os.environ.get("BACKFILL_VENDOR_LIMIT", "500"))
    gap = _GAP_KEY if api_key else _GAP_NO_KEY

    logger.info("=" * 60)
    logger.info(f"영향 벤더 백필 시작 (NVD 키 {'있음' if api_key else '없음'} · 건당 {gap}초)")
    logger.info("=" * 60)

    db = ArgusDB()
    rows = db.get_rows_missing_vendor()
    if not rows:
        logger.info("벤더가 빠진 행이 없습니다 — 종료")
        return 0

    targets = rows[:limit]
    logger.info(f"대상 {len(rows):,}건 중 이번 실행 {len(targets):,}건 "
                f"(예상 {len(targets) * gap / 60:.0f}분)")

    updates, hit, miss = [], 0, 0
    for i, row in enumerate(targets, 1):
        cve_id = row.get("id")
        state = row.get("last_alert_state")
        if not cve_id or not state:
            continue
        affected = _fetch_cpe(cve_id, api_key, state.get("affected"))
        if affected:
            hit += 1
            new_state = dict(state)
            new_state["affected"] = affected
            updates.append({"id": cve_id, "last_alert_state": new_state})
            logger.info(f"  [{i}/{len(targets)}] {cve_id} → "
                        f"{affected[0]['vendor']} / {affected[0]['product']}")
        else:
            miss += 1
        if i < len(targets):
            time.sleep(gap)

    ok = db.bulk_save_states(updates, "영향 벤더")
    if ok:
        db.request_full_export()
    logger.info("=" * 60)
    logger.info(f"벤더 백필 완료: 복구 {hit:,} · NVD에도 없음 {miss:,} · 저장 {ok:,}건")
    if len(rows) > len(targets):
        logger.info(f"남은 대상 {len(rows) - len(targets):,}건 — 다시 실행하면 이어서 처리합니다")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
