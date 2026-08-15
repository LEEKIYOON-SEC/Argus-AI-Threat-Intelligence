"""영향 벤더 소급 백필 — 수동 실행 전용 (workflow_dispatch).

원본 CNA 레코드가 벤더/제품을 'n/a'로 두는 경우가 있다(MITRE 할당 레코드에 흔하다).
그때도 NVD CPE에는 값이 들어 있곤 한다 — 예:

    CVE-2020-29574  CNA: vendor="n/a"  →  NVD CPE: cpe:2.3:o:sophos:cyberoamos

파이프라인은 이제 수집 시점에 이걸 채우지만, 그 전에 저장된 행은 벤더가 빈 채로 남아
대시보드 벤더 필터에서 통째로 빠진다(실측 198건, 추적 CVE의 1.6%). 이 스크립트가
한 번에 채운다.

공개일 백필과 달리 범위 조회를 쓸 수 없다 — CPE는 CVE 단건 조회로만 온다. 대상이
수백 건 규모라 감당 가능하지만, NVD 키가 없으면 건당 8초라 200건에 27분쯤 걸린다.

실패해도 안전하다 — 아무것도 지우지 않고 affected가 비어 있는 행에만 값을 더한다.
"""
import os
import sys
import time
from typing import Dict, List

import requests

from collector import affected_from_cpes
from database import ArgusDB
from logger import logger

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# API 키 없으면 30초당 5회 제한 → 넉넉히 8초. 키가 있으면 0.7초.
_GAP_NO_KEY, _GAP_KEY = 8.0, 0.7


def _fetch_cpe(cve_id: str, api_key: str) -> List[Dict]:
    """NVD에서 CVE 하나의 CPE를 받아 affected 항목으로 변환. 실패하면 빈 리스트."""
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
    # 변환 규칙은 수집 파이프라인과 공유한다 — 두 경로가 다른 벤더명을 만들면 안 된다
    return affected_from_cpes(cpes)


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

    # 최신순으로 왔으므로 상한을 걸면 최근 것부터 채워진다 — 도중에 끊겨도 눈에 띄는
    # 쪽이 먼저 복구된다. 남은 건 다시 실행하면 이어서 처리된다.
    targets = rows[:limit]
    logger.info(f"대상 {len(rows):,}건 중 이번 실행 {len(targets):,}건 "
                f"(예상 {len(targets) * gap / 60:.0f}분)")

    updates, hit, miss = [], 0, 0
    for i, row in enumerate(targets, 1):
        cve_id = row.get("id")
        state = row.get("last_alert_state")
        if not cve_id or not state:
            continue
        affected = _fetch_cpe(cve_id, api_key)
        if affected:
            hit += 1
            new_state = dict(state)
            new_state["affected"] = affected
            updates.append({"id": cve_id, "last_alert_state": new_state})
            logger.info(f"  [{i}/{len(targets)}] {cve_id} → "
                        f"{affected[0]['vendor']} / {affected[0]['product']}")
        else:
            miss += 1   # NVD에도 CPE가 없는 건 — 방법이 없다
        if i < len(targets):
            time.sleep(gap)

    ok = db.bulk_save_states(updates, "영향 벤더")
    logger.info("=" * 60)
    logger.info(f"벤더 백필 완료: 복구 {hit:,} · NVD에도 없음 {miss:,} · 저장 {ok:,}건")
    if len(rows) > len(targets):
        logger.info(f"남은 대상 {len(rows) - len(targets):,}건 — 다시 실행하면 이어서 처리합니다")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
