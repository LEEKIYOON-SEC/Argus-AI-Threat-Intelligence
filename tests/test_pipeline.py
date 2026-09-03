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

    silent_mode(failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


class SaveDB:
    def __init__(self): self.saved = {}
    def get_cve(self, cid): return self.saved.get(cid)
    def get_cves(self, ids):
        return {c: self.saved[c] for c in ids if c in self.saved}, set(ids)
    def upsert_cve(self, payload):
        self.saved.setdefault(payload["id"], {}).update(payload)
        return True


class Notifier:
    def __init__(self): self.sent = []
    def send_alert(self, state, reason, url=None, tier=None):
        self.sent.append(state["id"])


def silent_mode(failures):
    kev = {"id": "CVE-2020-1472", "cvss": 10.0, "epss": 0.9, "is_kev": True,
           "title": "Zerologon",
           "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}

    print("\n── 소급 채우기 (silent=True) ──")
    db, notifier = SaveDB(), Notifier()
    out = pipeline.process(dict(kev), db, None, silent=True)
    row = db.saved["CVE-2020-1472"]
    state = row["last_alert_state"]
    check(out.tier == "T0", f"티어는 정상 판정된다 (={out.tier})", failures)
    check(out.status == "tracked", f"상태는 tracked — alerted 가 아니다 (={out.status})", failures)
    check("last_alert_at" not in row,
          "last_alert_at 을 남기지 않는다 → 리포트 대량 생성이 안 걸린다", failures)
    check("kev" in state["fired_triggers"],
          f"fired_triggers 는 기록한다 (={state['fired_triggers']})", failures)
    check(row["is_kev"] is True, "대시보드에 '악용 중'으로 뜬다", failures)

    print("\n── 소급 뒤 정상 실행 ──")
    pipeline.process(dict(kev), db, notifier)
    check(not notifier.sent, f"같은 신호로는 재알림이 없다 (보낸 것 {notifier.sent})", failures)

    kev_msf = dict(kev, has_metasploit_module=True)
    pipeline.process(kev_msf, db, notifier)
    check(notifier.sent == ["CVE-2020-1472"],
          "새 트리거(Metasploit)가 붙으면 그때는 알림이 나간다", failures)
    check("last_alert_at" in db.saved["CVE-2020-1472"],
          "그 시점에 비로소 last_alert_at 이 기록된다", failures)

    print("\n── 대조: 평소 경로 ──")
    db2, n2 = SaveDB(), Notifier()
    pipeline.process(dict(kev), db2, n2)
    check(n2.sent == ["CVE-2020-1472"], "silent 없이는 알림이 나간다", failures)
    check("last_alert_at" in db2.saved["CVE-2020-1472"],
          "silent 없이는 last_alert_at 이 기록된다", failures)


if __name__ == "__main__":
    sys.exit(main())
