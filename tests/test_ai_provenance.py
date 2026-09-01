#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import ai_provenance as ap

SHOULD_HIT = [
    (["Red Hat would like to thank Google Big Sleep for reporting this issue."],
     "Google Big Sleep"),
    (["Nicholas Carlini using Claude, Anthropic"], "Anthropic / Claude"),
    (["Thai Duong (Calif.io in collaboration with Claude and Anthropic Research)"],
     "Anthropic / Claude"),
    (["Red Hat would like to thank John Walker (ZeroPath) and Ron Ben Yizhak (SafeBreach) "
      "for reporting this issue."], "ZeroPath"),
    (["Found by XBOW"], "XBOW"),
]

SHOULD_MISS = [
    ["Kostya Kortchinsky | OpenAI"],
    ["George Chen"],
    ["WPScan"],
    ["Professor Le Yu of Nanjing University of Posts and Telecommunications"],
    ["reported by an AI enthusiast"],
    ["Anthropic Inc. is not involved"],
    ["automated fuzzing found this"],
    [],
    None,
]


def check(cond, msg, failures):
    if not cond:
        failures.append(msg)
        print(f"  FAIL {msg}")
    else:
        print(f"  OK   {msg}")


def main() -> int:
    failures = []

    print("── 잡아야 하는 것 ──")
    for credits, expected in SHOULD_HIT:
        got = ap.credit_provenance(credits)
        check(got is not None and got.program == expected,
              f"{str(credits[0])[:52]:54s} → {got.program if got else '없음'}", failures)
        if got:
            check(got.detail == credits[0].strip(),
                  "  근거(크레딧 원문)를 그대로 보존한다", failures)

    print("\n── 오탐이면 안 되는 것 ──")
    for credits in SHOULD_MISS:
        got = ap.credit_provenance(credits)
        check(got is None, f"{str(credits)[:54]:56s} → {got.program if got else '미검출'}",
              failures)

    print("\n── Anthropic 레저 ──")
    ledger = {"CVE-2026-12340": {"ant_id": "ANT-2026-87DJGDRB",
                                 "project": "wolfssl/wolfssl",
                                 "bug_class": "heap-buffer-overflow",
                                 "severity": "low", "title": "t", "revealed_at": "", "count": 1}}
    p = ap.anthropic_provenance("CVE-2026-12340", ledger)
    check(p is not None and p.program == "Anthropic CVD", "레저 항목을 찾는다", failures)
    check(p is not None and "ANT-2026-87DJGDRB" in p.detail, "ANT ID를 근거로 싣는다", failures)
    check(ap.anthropic_provenance("CVE-2000-0001", ledger) is None,
          "레저에 없는 CVE는 None", failures)
    check(ap.anthropic_provenance("CVE-2026-12340", None) is None,
          "레저 미적재(None)면 조용히 None — 크레딧 경로로 넘어간다", failures)

    print("\n── 우선순위 ──")
    both = ap.detect("CVE-2026-12340", ["Found by XBOW"], ledger)
    check(both is not None and both.program == "Anthropic CVD",
          "구조화된 레저가 자유텍스트 크레딧보다 우선한다", failures)
    only_credit = ap.detect("CVE-2000-0001", ["Found by XBOW"], ledger)
    check(only_credit is not None and only_credit.program == "XBOW",
          "레저에 없으면 크레딧으로 판정한다", failures)
    check(ap.detect("CVE-2000-0001", ["George Chen"], ledger) is None,
          "둘 다 아니면 None", failures)

    print("\n── 상태 직렬화 ──")
    st = ap.Provenance("X", "d" * 500, "u").as_state()
    check(st["ai_discovered"] is True and st["ai_program"] == "X", "상태 dict 형식", failures)
    check(len(st["ai_detail"]) == 300, "detail은 300자로 자른다 (DB 용량)", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
