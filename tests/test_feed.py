#!/usr/bin/env python3
"""feed.py 파싱 회귀 테스트 — 네트워크 없이 합성 데이터로 돌린다.

    python3 tests/test_feed.py

지키는 것은 모듈 주석에 적힌 '두 함정'이다.
  · 배치 fetchTime 기준으로 걸러야 한다 (dateUpdated 기준이면 실측 6.4%가 사라진다)
  · Range로 잘린 JSON 배열에서 완성된 객체만 뽑아야 한다
"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import pytz  # noqa: E402

import feed  # noqa: E402


def ts(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))


def item(cve, updated):
    return {"cveId": cve, "dateUpdated": updated,
            "githubLink": f"https://example/{cve}.json"}


BATCHES = [
    # 최신순 (deltaLog와 같은 순서)
    {"fetchTime": "2026-08-30T12:00:00.000Z", "new": [item("CVE-2026-3", "2026-08-30T11:58:00.000Z")],
     "updated": []},
    {"fetchTime": "2026-08-30T11:00:00.000Z", "new": [],
     # ★ 핵심: 배치는 11:00인데 레코드가 밝힌 시각은 6시간 전이다.
     #   dateUpdated로 거르면 이 항목이 사라진다.
     "updated": [item("CVE-2026-2", "2026-08-30T05:00:00.000Z")]},
    {"fetchTime": "2026-08-30T10:00:00.000Z", "new": [item("CVE-2026-1", "2026-08-30T09:59:00.000Z")],
     "updated": []},
    {"fetchTime": "2026-08-30T08:00:00.000Z", "new": [item("CVE-2026-0", "2026-08-30T07:59:00.000Z")],
     "updated": []},
]


def check(cond, msg, failures):
    if not cond:
        failures.append(msg)
        print(f"  FAIL {msg}")
    else:
        print(f"  OK   {msg}")


def main() -> int:
    failures = []
    far = ts("2030-01-01T00:00:00Z")

    print("── 배치 시각 기준 수집 ──")
    changes, horizon = feed._collect(BATCHES, ts("2026-08-30T09:00:00Z"), far)
    ids = [c.cve_id for c in changes]
    check(ids == ["CVE-2026-1", "CVE-2026-2", "CVE-2026-3"],
          f"09:00 이후 배치만, 오래된 순: {ids}", failures)
    check("CVE-2026-2" in ids,
          "dateUpdated가 창 밖이어도 배치가 창 안이면 포함해야 한다 (누락 0)", failures)
    check(horizon == ts("2026-08-30T12:00:00Z"), f"horizon은 최신 배치 시각: {horizon}", failures)

    print("\n── 경계 ──")
    changes, _ = feed._collect(BATCHES, ts("2026-08-30T10:00:00Z"), far)
    check([c.cve_id for c in changes] == ["CVE-2026-2", "CVE-2026-3"],
          "since와 정확히 같은 시각의 배치는 이미 소비된 것으로 본다", failures)

    changes, horizon = feed._collect(BATCHES, ts("2026-08-30T09:00:00Z"),
                                     ts("2026-08-30T11:00:00Z"))
    check([c.cve_id for c in changes] == ["CVE-2026-1", "CVE-2026-2"],
          "until 상한 밖의 배치는 제외 (다음 실행이 이어받는다)", failures)
    check(horizon == ts("2026-08-30T11:00:00Z"), "horizon이 until을 넘지 않는다", failures)

    print("\n── 같은 CVE가 여러 배치에 ──")
    dup = [
        {"fetchTime": "2026-08-30T12:00:00.000Z", "new": [],
         "updated": [item("CVE-2026-9", "2026-08-30T11:55:00.000Z")]},
        {"fetchTime": "2026-08-30T10:00:00.000Z",
         "new": [item("CVE-2026-9", "2026-08-30T09:55:00.000Z")], "updated": []},
    ]
    changes, _ = feed._collect(dup, ts("2026-08-30T09:00:00Z"), far)
    check(len(changes) == 1 and changes[0].batch_at == ts("2026-08-30T12:00:00Z"),
          "가장 최신 배치 하나로 접는다", failures)
    check(changes[0].is_new, "한 번이라도 new였으면 신규로 표시한다", failures)

    print("\n── 잘린 JSON 배열 앞부분 파싱 ──")
    full = json.dumps(BATCHES)
    check(len(feed._parse_array_prefix(full)) == 4, "온전한 배열은 전부 파싱", failures)
    truncated = full[:len(full) // 2]
    got = feed._parse_array_prefix(truncated)
    check(0 < len(got) < 4, f"잘린 배열에서 완성된 객체만 뽑는다 ({len(got)}건)", failures)
    check(all(isinstance(b, dict) and "fetchTime" in b for b in got),
          "뽑힌 객체는 전부 온전하다", failures)
    check(feed._parse_array_prefix("not json") == [], "쓰레기 입력은 빈 목록", failures)
    check(feed._parse_array_prefix("") == [], "빈 입력은 빈 목록", failures)

    print("\n── 워터마크 없음 / 미래 ──")
    now = datetime.datetime.now(pytz.UTC)
    changes, horizon = feed.changes_since(now + datetime.timedelta(hours=1), now=now)
    check(changes == [] and horizon == now, "미래 워터마크는 즉시 빈 결과", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
