"""CVE 공개일 소급 백필 — 수동 실행 전용 (workflow_dispatch).

추이 차트를 '우리가 확인한 날'이 아니라 'CVE가 공개된 날' 기준으로 바꾸면서, 이미
저장된 행에는 공개일이 없어 차트가 비게 된다. 이 스크립트가 한 번에 채운다.

NVD의 날짜 범위 조회를 쓴다. CVE를 하나씩 읽으면 수천 번 호출이지만, 범위 조회는
2,000건씩 받아오므로 수십 번이면 끝난다. 받은 것 중 우리 DB에 있는 CVE만 갱신한다.

한 번 돌리고 나면 이후로는 파이프라인이 수집 시점에 채우므로 다시 실행할 일이 없다.
(실패해도 안전하다 — 아무것도 지우지 않고 published 키만 더한다.)
"""
import datetime
import os
import sys
import time
from typing import Dict

import requests

from database import ArgusDB
from logger import logger

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PAGE = 2000
# API 키 없으면 30초당 5회 제한 → 넉넉히 8초. 키가 있으면 0.7초.
_GAP_NO_KEY, _GAP_KEY = 8.0, 0.7


def _fetch_window(start: datetime.datetime, end: datetime.datetime,
                  api_key: str) -> Dict[str, str]:
    """NVD에서 [start, end) 공개 CVE의 {id: 공개일} 수집. 실패해도 예외 없이 빈 dict."""
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
            return out

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
    return out


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

    # 최신 구간부터 — 도중에 중단돼도 차트에서 눈에 띄는 쪽이 먼저 채워진다
    now = datetime.datetime.now(datetime.timezone.utc)
    published: Dict[str, str] = {}
    step = 30
    for off in range(0, days, step):
        end = now - datetime.timedelta(days=off)
        start = now - datetime.timedelta(days=min(off + step, days))
        got = _fetch_window(start, end, api_key)
        hit = {k: v for k, v in got.items() if k in targets}
        published.update(hit)
        logger.info(f"  {start:%Y-%m-%d} ~ {end:%Y-%m-%d}: 수집 {len(got):,} · 우리 것 {len(hit):,} "
                    f"(누적 {len(published):,}/{len(targets):,})")
        if len(published) >= len(targets):
            break
        time.sleep(_GAP_KEY if api_key else _GAP_NO_KEY)

    if not published:
        logger.warning("채울 공개일을 하나도 못 받았습니다 — 저장 생략")
        return 1

    ok = db.bulk_set_published(rows, published)
    if ok:
        # updated_at을 건드리지 않으므로 증분 export가 이 변경을 못 본다 → 전량 1회 요청
        db.request_full_export()
    logger.info("=" * 60)
    logger.info(f"백필 완료: {ok:,}/{len(targets):,}건 갱신")
    logger.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
