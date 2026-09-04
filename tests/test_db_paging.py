#!/usr/bin/env python3
import os
import random
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
for _k in ("SUPABASE_URL", "SUPABASE_KEY"):
    os.environ.setdefault(_k, "test")

import database  # noqa: E402


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


class Table:
    def __init__(self, store, fail_at=None):
        self.store = store
        self.fail_at = fail_at
        self._order = None
        self._desc = False

    def select(self, *a, **k):
        return self

    def not_(self):
        return self

    @property
    def is_(self):
        return lambda *a, **k: self

    def order(self, field, desc=False):
        self._order = field
        self._desc = desc
        return self

    def range(self, lo, hi):
        self._lo, self._hi = lo, hi
        return self

    def execute(self):
        if self.fail_at is not None and self._lo >= self.fail_at:
            raise RuntimeError("연결 끊김")
        rows = sorted(self.store.rows, key=lambda r: r[self._order],
                      reverse=self._desc)
        page = rows[self._lo:self._hi + 1]
        self.store.writes_during_paging()
        return type("R", (), {"data": [dict(r) for r in page]})()


class Store:
    def __init__(self, n, churn=0, fail_at=None):
        self.rows = [{"id": f"CVE-2026-{i:05d}", "updated_at": i,
                      "last_alert_state": {"tier": "T2"}} for i in range(n)]
        self.churn = churn
        self.clock = n
        self.fail_at = fail_at
        self.rng = random.Random(7)

    def writes_during_paging(self):
        for _ in range(self.churn):
            self.clock += 1
            self.rng.choice(self.rows)["updated_at"] = self.clock

    def table(self, name):
        t = Table(self, self.fail_at)
        t.not_ = t
        return t


class FakeDB(database.ArgusDB):
    def __init__(self, store):
        self.client = store

    def _execute(self, query):
        return query.execute()


def stable_key(failures):
    print("── 페이징 중에 다른 레인이 쓰는 경우 ──")
    n = 5000
    for churn in (0, 5, 20):
        store = Store(n, churn=churn)
        ids = FakeDB(store).get_tracked_ids(page_size=1000)
        missing = n - len(set(ids))
        dup = len(ids) - len(set(ids))
        print(f"    페이지당 쓰기 {churn:>2}건 → 누락 {missing}건 · 중복 {dup}건")
        check(missing == 0 and dup == 0,
              f"쓰기 {churn}건/페이지에도 누락·중복이 없다 "
              f"(updated_at 으로 정렬하면 행이 페이지 사이를 넘나든다)", failures)


def failure_is_not_absence(failures):
    print("\n── 페이징 도중 조회가 실패하면 ──")
    store = Store(5000, fail_at=2000)
    try:
        FakeDB(store).tracked_states(page_size=1000)
        check(False, "부분 결과를 조용히 돌려줬다 — '못 봤음'이 '없음'이 된다", failures)
    except RuntimeError:
        check(True, "예외를 올린다 — 호출자가 덮어쓰기를 멈춘다", failures)

    store_ok = Store(2500)
    rows = FakeDB(store_ok).tracked_states(page_size=1000)
    check(len(rows) == 2500, f"정상일 때는 전량을 돌려준다 ({len(rows)}건)", failures)

    print("\n── 백필들이 그 예외를 삼키지 않는가 ──")
    import ast
    import pathlib
    for name, call in (("backfill_signals.py", "tracked_states"),
                       ("backfill_cvss.py", "get_rows_needing_cvss"),
                       ("backfill_vendors.py", "get_rows_missing_vendor"),
                       ("backfill_published.py", "get_rows_missing_published")):
        src = (pathlib.Path(ROOT) / "src" / name).read_text(encoding="utf-8")
        tree = ast.parse(src)
        wrapped = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            for sub in ast.walk(node):
                if (isinstance(sub, ast.Attribute) and sub.attr == call
                        and any(isinstance(h.body[0], (ast.Return, ast.Pass))
                                for h in node.handlers if h.body)):
                    wrapped = True
        check(not wrapped,
              f"{name}: {call}() 실패를 try/except 로 삼켜 정상 종료하지 않는다", failures)


def main() -> int:
    failures = []
    stable_key(failures)
    failure_is_not_absence(failures)
    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
