import datetime
import os
import sys
import time
from typing import Dict, Tuple

import requests

from database import ArgusDB
from logger import logger

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000
_GAP_NO_KEY, _GAP_KEY = 8.0, 0.7


def _fetch_window(start: datetime.datetime, end: datetime.datetime,
                  api_key: str) -> Tuple[Dict[str, str], bool]:
    headers = {"apiKey": api_key} if api_key else {}
    out: Dict[str, str] = {}
    idx = 0
    while True:
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": _PAGE,
            "startIndex": idx,
        }
        try:
            r = requests.get(_NVD, params=params, headers=headers, timeout=90)
            r.raise_for_status()
            data = r.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.warning(f"  NVD 조회 실패 ({start:%Y-%m-%d}): {e}")
            return out, False

        for item in data.get("vulnerabilities", []) or []:
            cve = item.get("cve") or {}
            cid, pub = cve.get("id"), cve.get("published")
            if cid and pub:
                out[cid] = str(pub)[:10]

        total = data.get("totalResults", 0)
        idx += _PAGE
        if idx >= total:
            break
        time.sleep(_GAP_KEY if api_key else _GAP_NO_KEY)
    return out, True


def main() -> int:
    api_key = os.environ.get("NVD_API_KEY", "")
    days = int(os.environ.get("BACKFILL_DAYS", "400"))
    logger.info("=" * 60)
    logger.info(f"공개일 백필 시작 (최근 {days}일 · NVD 키 {'있음' if api_key else '없음'})")
    logger.info("=" * 60)

    db = ArgusDB()
    rows = db.get_rows_missing_published()
    if not rows:
        logger.info("공개일이 빠진 행이 없습니다 — 종료")
        return 0
    targets = {r["id"]: r for r in rows}
    logger.info(f"대상 {len(targets):,}건")

    now = datetime.datetime.now(datetime.timezone.utc)
    published: Dict[str, str] = {}
    step = 30
    windows = fetched = 0
    for off in range(0, days, step):
        end = now - datetime.timedelta(days=off)
        start = now - datetime.timedelta(days=min(off + step, days))
        got, ok_window = _fetch_window(start, end, api_key)
        windows += 1 if ok_window else 0
        fetched += len(got)
        hit = {k: v for k, v in got.items() if k in targets}
        published.update(hit)
        logger.info(f"  {start:%Y-%m-%d} ~ {end:%Y-%m-%d}: 수집 {len(got):,} · 우리 것 {len(hit):,} "
                    f"(누적 {len(published):,}/{len(targets):,})")
        if len(published) >= len(targets):
            break
        time.sleep(_GAP_KEY if api_key else _GAP_NO_KEY)

    if not published:
        if windows == 0 or fetched == 0:
            logger.warning("NVD에서 아무것도 받지 못했습니다 — 조회 실패")
            return 1
        logger.info(f"최근 {days}일 창에 해당하는 대상이 없습니다 "
                    f"(NVD {fetched:,}건 조회 · 겹침 0). 남은 {len(targets):,}건은 더 과거의 "
                    f"CVE이므로 BACKFILL_DAYS를 늘려 다시 실행하세요.")
        return 0

    ok = db.bulk_set_published(rows, published)
    if ok:
        db.request_full_export()
    logger.info("=" * 60)
    logger.info(f"백필 완료: {ok:,}/{len(targets):,}건 갱신")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
