#!/usr/bin/env python3
"""CVSS 소급 보정 — 옛 행을 고치되, 낮추지도 알리지도 않는지.

    python3 tests/test_backfill_cvss.py

왜 있나: 옛 코드는 metrics 를 돌다 CVSS 를 하나 만나면 거기서 끊었다. 그래서 4.0 블록이
먼저 오면 3.x 를 못 봤고, 4.0 에 baseScore 가 없으면 점수가 통째로 N/A 로 남았다.
지금 파이프라인은 고쳤지만 **이미 저장된 행은 그 값을 그대로 갖고 있다** — 새로 처리되는
CVE 부터만 맞다. 그 간극을 메우는 게 src/backfill_cvss.py 다.

여기서 지키는 계약 셋:

1. **점수를 내리지 않는다.** 이 도구의 일은 버려진 버전을 되찾는 것이지 레코드를 다시
   동기화하는 게 아니다. 소스가 진짜로 하향 수정됐다면 delta 피드가 정상 경로로 고친다.
   특히 NVD 보충으로 받은 점수는 cvelistV5 레코드에 아예 없어서, 낮추기를 허용하면
   멀쩡한 9.8 이 0.0 으로 지워진다.
2. **알림을 켤 수 없다.** CVSS 가 건드리는 트리거는 cvss_critical_remote 와
   unscored_major_cna 뿐이고 둘 다 T2 다. 알림은 T0/T1 트리거만 낸다. 이건 우연이
   아니라 지켜야 할 성질이라서 여기서 전수로 확인한다.
3. **한 번 처리한 행은 다시 안 잡힌다.** 대상 선정 기준이 cvss_version 키의 유무이므로,
   점수가 안 변해도 키는 반드시 심어야 한다. 안 그러면 매 실행이 같은 행을 다시 받아온다.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import risk  # noqa: E402
from backfill_cvss import _priority, recompute, version_of  # noqa: E402


def rec(cna=None, adp=None):
    c = {}
    if cna is not None:
        c["cna"] = {"metrics": [{k: v} for k, v in cna.items()]}
    if adp is not None:
        c["adp"] = [{"metrics": [{k: v} for k, v in adp.items()]}]
    return {"containers": c}


def blk(score, vector):
    return {"baseScore": score, "vectorString": vector}


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    failures = []

    print("── 벡터에서 버전을 읽는다 ──")
    for vector, want in (("CVSS:3.1/AV:N/AC:L", "3.1"), ("CVSS:4.0/AV:N/AC:L", "4.0"),
                         ("CVSS:3.0/AV:N", "3.0"), ("N/A", ""), ("", ""), (None, "")):
        got = version_of(vector)
        check(got == want, f"{vector!r} → {got!r}", failures)

    print("\n── 사용자가 본 증상: 3.x 는 9.8 인데 화면은 N/A ──")
    # 옛 코드가 죽던 모양 그대로 — 4.0 블록이 먼저 오는데 baseScore 가 없다.
    state = {"id": "CVE-X", "cvss": 0.0, "cvss_vector": "N/A", "tier": risk.T2,
             "assigner": "microsoft", "fired_triggers": []}
    record = {"containers": {"cna": {"metrics": [
        {"cvssV4_0": {"vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N"}},
        {"cvssV3_1": blk(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N")},
    ]}}}
    new = recompute(state, record)
    check(new["cvss"] == 9.8, f"점수가 복구된다 (0.0 → {new['cvss']})", failures)
    check(new["cvss_version"] == "3.1", f"버전이 붙는다 (v{new['cvss_version']})", failures)
    check(new["cvss_vector"].startswith("CVSS:3.1"), "벡터도 채택한 버전의 것", failures)

    print("\n── 4.0 만 읽고 끊어서 3.x 가 더 높았던 행 ──")
    state = {"id": "CVE-Y", "cvss": 9.4, "cvss_vector": "CVSS:4.0/AV:N/AC:L", "tier": risk.T3}
    new = recompute(state, rec(cna={"cvssV4_0": blk(9.4, "CVSS:4.0/AV:N/AC:L"),
                                   "cvssV3_1": blk(9.9, "CVSS:3.1/AV:N/AC:L")}))
    check(new["cvss"] == 9.9 and new["cvss_version"] == "3.1",
          f"더 높은 3.1 로 올라간다 ({new['cvss']} v{new['cvss_version']})", failures)
    check(set(new["cvss_scores"]) == {"4.0", "3.1"}, "두 버전이 다 남는다 (화면 병기용)", failures)

    print("\n── CNA 가 4.0 만 내도 ADP(CISA)의 3.1 을 살린다 ──")
    state = {"id": "CVE-Z", "cvss": 8.7, "cvss_vector": "CVSS:4.0/AV:N"}
    new = recompute(state, rec(cna={"cvssV4_0": blk(8.7, "CVSS:4.0/AV:N")},
                               adp={"cvssV3_1": blk(9.8, "CVSS:3.1/AV:N")}))
    check(new["cvss"] == 9.8, f"ADP 점수가 반영된다 ({new['cvss']})", failures)

    print("\n── 점수를 내리지 않는다 ──")
    cases = (
        ("레코드에 CVSS 가 아예 없다 (NVD 보충으로 받은 값)",
         {"id": "A", "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N"}, rec(cna={}), 9.8),
        ("레코드가 더 낮은 값만 갖고 있다",
         {"id": "B", "cvss": 9.8, "cvss_vector": "CVSS:3.1/AV:N"},
         rec(cna={"cvssV3_1": blk(5.3, "CVSS:3.1/AV:L")}), 9.8),
        ("버전을 알 수 없는 옛 점수가 더 높다",
         {"id": "C", "cvss": 9.1, "cvss_vector": "N/A"},
         rec(cna={"cvssV4_0": blk(7.5, "CVSS:4.0/AV:N")}), 9.1),
        ("컨테이너가 통째로 비었다", {"id": "D", "cvss": 7.2, "cvss_vector": "CVSS:3.0/AV:N"},
         {"containers": {}}, 7.2),
    )
    for desc, st, record, want in cases:
        new = recompute(st, record)
        check(new["cvss"] == want, f"{desc} → {new['cvss']} (그대로)", failures)

    print("\n── 항상 cvss_version 키를 심는다 (같은 행을 다시 안 붙잡게) ──")
    for desc, st, record in (("점수가 안 변해도", {"id": "E", "cvss": 7.2,
                                                "cvss_vector": "CVSS:3.1/AV:N"}, rec(cna={})),
                             ("점수가 0 이고 소스에도 없어도", {"id": "F", "cvss": 0.0,
                                                        "cvss_vector": "N/A"}, rec(cna={}))):
        new = recompute(st, record)
        check("cvss_version" in new, f"{desc} 키가 생긴다 ({new['cvss_version']!r})", failures)
        check("cvss_scores" in new and "tier" in new, f"{desc} scores·tier 도 채워진다", failures)

    print("\n── 저장된 다른 신호를 하나도 잃지 않는다 ──")
    st = {"id": "G", "cvss": 0.0, "cvss_vector": "N/A", "is_kev": True,
          "title": "제목", "affected": [{"vendor": "V", "product": "P"}],
          "fired_triggers": ["kev"], "epss": 0.42, "has_nuclei_template": True}
    new = recompute(st, rec(cna={"cvssV3_1": blk(9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N")}))
    kept = all(new.get(k) == st[k] for k in
               ("is_kev", "title", "affected", "fired_triggers", "epss", "has_nuclei_template"))
    check(kept, "CVSS 4개 키와 tier 외에는 그대로다", failures)
    check(new["tier"] == risk.T0, f"KEV 행은 T0 를 유지한다 ({new['tier']})", failures)

    print("\n── 알림 트리거를 새로 켤 수 없다 (구조적 성질) ──")
    # CVSS 가 건드리는 트리거를 전수로 확인한다. 여기에 T0/T1 이 하나라도 들어오면
    # 이 도구가 조용히 알림을 만들 수 있다는 뜻이므로 즉시 알아야 한다.
    touched = {"cvss_critical_remote", "unscored_major_cna"}
    for key in touched:
        t = risk.TRIGGERS[key]
        check(t.tier == risk.T2, f"{key} 는 T2 ({t.tier})", failures)
    check(not (touched & risk.ALERTING_TRIGGERS),
          "CVSS 로 켜지는 트리거 중 알림용은 없다", failures)

    base = {"id": "H", "is_kev": False, "assigner": "microsoft", "cwe": ["CWE-78"],
            "epss": 0.0, "epss_percentile": 0.0}
    for score, vector in ((0.0, "N/A"), (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"),
                          (5.3, "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A"), (10.0, "CVSS:4.0/AV:N")):
        before = risk.evaluate(base).alerting_triggers
        after = risk.evaluate(dict(base, cvss=score, cvss_vector=vector)).alerting_triggers
        check(before == after, f"CVSS {score} 로 바꿔도 알림 트리거 불변 ({sorted(after)})", failures)

    print("\n── 점수를 찾으면 '재평가 대기'(T2) 사유가 사라진다 ──")
    st = {"id": "I", "cvss": 0.0, "cvss_vector": "N/A", "assigner": "oracle", "cwe": []}
    check(risk.evaluate(st).tier == risk.T2, "점수 없는 주요 CNA 는 T2 로 잡혀 있었다", failures)
    new = recompute(st, rec(cna={"cvssV3_1": blk(6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R")}))
    check(new["tier"] == risk.T3, f"6.5 로 확인되면 T3 로 내려간다 ({new['tier']})", failures)

    print("\n── 급한 것부터 처리한다 ──")
    rows = [
        {"id": "low", "last_alert_state": {"tier": risk.T3, "cvss": 5.0}},
        {"id": "kev-scored", "last_alert_state": {"tier": risk.T0, "cvss": 9.8}},
        {"id": "kev-na", "last_alert_state": {"tier": risk.T0, "cvss": 0.0}},
        {"id": "t2", "last_alert_state": {"tier": risk.T2, "cvss": 7.0}},
    ]
    order = [r["id"] for r in sorted(rows, key=_priority)]
    check(order == ["kev-na", "kev-scored", "t2", "low"], f"순서: {order}", failures)

    print("\n── 깨진 입력에도 안 터진다 ──")
    for desc, st, record in (
        ("record 가 빈 dict", {"id": "X", "cvss": 0.0}, {}),
        ("containers 가 None", {"id": "X", "cvss": 0.0}, {"containers": None}),
        ("adp 가 리스트가 아님", {"id": "X", "cvss": 0.0}, {"containers": {"adp": "??"}}),
        ("cvss 가 문자열", {"id": "X", "cvss": "9.8", "cvss_vector": "CVSS:3.1/AV:N"},
         rec(cna={})),
        ("cvss 가 None", {"id": "X", "cvss": None, "cvss_vector": None}, rec(cna={})),
        ("state 에 CVSS 키가 아예 없음", {"id": "X"}, rec(cna={"cvssV3_1": blk(7.5, "v")})),
    ):
        try:
            new = recompute(st, record)
            check("cvss_version" in new, f"{desc} → 처리됨 ({new['cvss']})", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
