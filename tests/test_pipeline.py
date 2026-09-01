#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import pipeline


class FakeDB:
    def __init__(self, rows, fail_ids=()):
        self.rows = rows
        self.fail_ids = set(fail_ids)
        self.single_calls = []

    def get_cves(self, ids):
        found, covered = {}, set()
        for cid in ids:
            if cid in self.fail_ids:
                continue
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
