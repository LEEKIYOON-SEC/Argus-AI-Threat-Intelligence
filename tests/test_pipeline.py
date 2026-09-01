#!/usr/bin/env python3
"""pipeline.RowCache — 직전 상태 조회의 의미론. 네트워크·DB 없이 돈다.

    python3 tests/test_pipeline.py

이 캐시는 성능을 위해 넣었지만, 여기서 지켜야 하는 것은 성능이 아니라 **안전**이다.

한 회차 변경분의 90.5%는 T3이라 애초에 DB에 없다(실측 590건 중 534건). 그런데도
CVE마다 db.get_cve()를 돌았고, 그 왕복이 fast-lane의 처리 상한을 300건에 묶어 두고
있었다. 밀린 물량을 따라잡아야 할 때 정확히 반대로 가는 구조였다.

일괄 조회로 바꾸면서 생기는 위험이 하나 있다. **'조회했는데 없다'와 '조회를 못 했다'를
같게 취급하면 안 된다.** 조회 실패를 '없다'로 처리하는 순간 직전 상태가 사라진 것처럼
보이고, 이미 알린 CVE가 신규로 판정돼 같은 알림이 다시 나간다. 반복 발화 억제를
통째로 무너뜨리는 경로라, 아래 '조회 실패' 절이 이 파일의 핵심이다.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import pipeline  # noqa: E402


class FakeDB:
    """일괄 조회는 지정한 청크에서만 성공하고, 나머지는 '조회 실패'로 남는다."""

    def __init__(self, rows, fail_ids=()):
        self.rows = rows
        self.fail_ids = set(fail_ids)
        self.single_calls = []          # 개별 폴백이 몇 번 일어났는지

    def get_cves(self, ids):
        found, covered = {}, set()
        for cid in ids:
            if cid in self.fail_ids:
                continue                # covered 에 넣지 않는다 = '모른다'
            covered.add(cid)
            if cid in self.rows:
                found[cid] = self.rows[cid]
        return found, covered

    def get_cve(self, cve_id):
        self.single_calls.append(cve_id)
        return self.rows.get(cve_id)


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    failures = []
    rows = {"CVE-A": {"id": "CVE-A", "last_alert_state": {"tier": "T0"}},
            "CVE-B": {"id": "CVE-B", "last_alert_state": {"tier": "T2"}}}

    print("── 일괄 조회가 성사된 경우 ──")
    db = FakeDB(rows)
    cache = pipeline.RowCache(db, ["CVE-A", "CVE-B", "CVE-C"])
    check(cache.get("CVE-A") == rows["CVE-A"], "있는 행은 그대로 돌려준다", failures)
    check(cache.get("CVE-C") is None, "조회했는데 없으면 None", failures)
    check(db.single_calls == [], "조회가 성사된 id는 개별 왕복을 하지 않는다", failures)

    print("\n── 조회 실패 (여기가 핵심) ──")
    db = FakeDB(rows, fail_ids=["CVE-A"])
    cache = pipeline.RowCache(db, ["CVE-A", "CVE-C"])
    got = cache.get("CVE-A")
    check(db.single_calls == ["CVE-A"], "실패한 id는 개별 조회로 폴백한다", failures)
    check(got == rows["CVE-A"],
          "폴백으로 직전 상태를 되찾는다 — '없음'으로 오인하면 중복 알림이 나간다", failures)
    check(cache.get("CVE-C") is None and db.single_calls == ["CVE-A"],
          "성사된 id는 폴백하지 않는다 (실패분만)", failures)

    print("\n── 조회하지 않은 id ──")
    db = FakeDB(rows)
    cache = pipeline.RowCache(db, ["CVE-C"])
    check(cache.get("CVE-B") == rows["CVE-B"],
          "선조회 목록에 없던 id도 개별 조회로 정확히 처리한다 "
          "(신호 스냅샷 대조가 변경분 밖의 CVE를 들고 온다)", failures)

    print("\n── 저장 후 무효화 ──")
    db = FakeDB(rows)
    cache = pipeline.RowCache(db, ["CVE-A"])
    cache.get("CVE-A")
    cache.forget("CVE-A")
    check(cache.get("CVE-A") == rows["CVE-A"] and db.single_calls == ["CVE-A"],
          "저장한 CVE는 다시 조회한다 — 한 회차에 같은 CVE가 두 번 올 수 있다", failures)

    print("\n── 빈 입력 ──")
    db = FakeDB(rows)
    cache = pipeline.RowCache(db, [])
    check(cache.get("CVE-A") == rows["CVE-A"] and db.single_calls == ["CVE-A"],
          "비워 두면 전부 개별 조회 (기존 동작과 같다)", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
