#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import signal_snapshot as ss


def make_source(key, ids):
    return ss.Source(key, key, True, "kev", lambda: (set(ids) if ids is not None else None))


def check(cond, msg, failures):
    if not cond:
        failures.append(msg)
        print(f"  FAIL {msg}")
    else:
        print(f"  OK   {msg}")


def sweep(store, source, **kw):
    saved = dict(ss.SOURCES)
    ss.SOURCES.clear()
    ss.SOURCES[source.key] = source
    try:
        return ss.sweep(store, **kw)
    finally:
        ss.SOURCES.clear()
        ss.SOURCES.update(saved)


def main() -> int:
    failures = []

    print("── 최초 기록은 조용해야 한다 ──")
    store = ss.MemoryStore()
    out = sweep(store, make_source("s", ["CVE-1", "CVE-2", "CVE-3"]))
    check(len(out) == 1 and out[0].bootstrapped and not out[0].added,
          "첫 실행은 전량을 저장만 하고 알리지 않는다", failures)
    check(store.get_snapshot_ids("s") == {"CVE-1", "CVE-2", "CVE-3"},
          "전량이 저장된다", failures)

    print("\n── digest 게이팅 ──")
    check(sweep(store, make_source("s", ["CVE-1", "CVE-2", "CVE-3"])) == [],
          "집합이 같으면 집합을 읽지도 않고 끝난다", failures)

    print("\n── 신규 감지 ──")
    out = sweep(store, make_source("s", ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"]))
    check(len(out) == 1 and out[0].added == ["CVE-4", "CVE-5"],
          f"새로 들어온 것만 (정렬): {out[0].added if out else None}", failures)

    print("\n── 부분 성공: 처리한 것만 반영 ──")
    ss.commit(store, out[0], ["CVE-4"])
    check(store.get_snapshot_ids("s") == {"CVE-1", "CVE-2", "CVE-3", "CVE-4"},
          "성공분만 '아는 것'에 더한다", failures)
    out = sweep(store, make_source("s", ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"]))
    check(len(out) == 1 and out[0].added == ["CVE-5"],
          "실패분은 다음 실행에서 다시 잡힌다 (누락 0)", failures)
    ss.commit(store, out[0], ["CVE-5"])

    print("\n── 수신 실패 ──")
    before = store.get_snapshot_ids("s")
    check(sweep(store, make_source("s", None)) == [], "실패한 소스는 결과에 없다", failures)
    check(store.get_snapshot_ids("s") == before,
          "실패해도 저장된 집합을 건드리지 않는다 (알림 폭풍 방지)", failures)

    print("\n── 합집합 저장: 신호가 빠졌다 돌아와도 재알림 없음 ──")
    out = sweep(store, make_source("s", ["CVE-1", "CVE-2"]))
    check(out == [], "제외만 일어나면 알릴 게 없다", failures)
    out = sweep(store, make_source("s", ["CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"]))
    check(out == [], "빠졌다 돌아온 신호는 재알림하지 않는다", failures)

    print("\n── 상한 ──")
    store2 = ss.MemoryStore({"s": {"CVE-0"}})
    many = [f"CVE-{i}" for i in range(50)]
    out = sweep(store2, make_source("s", many), cap=10)
    check(len(out[0].added) == 10 and out[0].total_added == 49,
          f"cap만큼만 처리하고 전체 건수는 보고한다 ({len(out[0].added)}/{out[0].total_added})",
          failures)
    ss.commit(store2, out[0], out[0].added)
    out = sweep(store2, make_source("s", many), cap=10)
    check(out[0].total_added == 39, "나머지는 다음 실행이 이어받는다", failures)

    print("\n── 한 소스의 장애가 나머지를 막지 않는다 ──")
    store3 = ss.MemoryStore({"a": {"X"}, "b": {"Y"}})

    def boom():
        raise RuntimeError("업스트림 폭발")

    saved = dict(ss.SOURCES)
    ss.SOURCES.clear()
    ss.SOURCES["a"] = ss.Source("a", "a", True, "kev", boom)
    ss.SOURCES["b"] = make_source("b", ["Y", "Z"])
    try:
        out = ss.sweep(store3)
    finally:
        ss.SOURCES.clear()
        ss.SOURCES.update(saved)
    check(len(out) == 1 and out[0].source.key == "b" and out[0].added == ["Z"],
          "예외가 난 소스만 건너뛰고 나머지는 대조된다", failures)

    print("\n── fast_only 분리 ──")
    store4 = ss.MemoryStore({"f": {"A"}, "s": {"B"}})
    saved = dict(ss.SOURCES)
    ss.SOURCES.clear()
    ss.SOURCES["f"] = ss.Source("f", "fast", True, "kev", lambda: {"A", "C"})
    ss.SOURCES["s"] = ss.Source("s", "slow", False, "kev", lambda: {"B", "D"})
    try:
        out = ss.sweep(store4, fast_only=True)
    finally:
        ss.SOURCES.clear()
        ss.SOURCES.update(saved)
    check(len(out) == 1 and out[0].source.key == "f",
          "fast-lane은 가벼운 소스만 본다", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
