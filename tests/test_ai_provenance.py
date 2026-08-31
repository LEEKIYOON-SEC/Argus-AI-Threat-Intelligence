#!/usr/bin/env python3
"""ai_provenance.py 회귀 테스트 — 네트워크 없이 돈다.

    python3 tests/test_ai_provenance.py

여기서 지키는 것은 **정밀도**다. 이 매처는 자유텍스트(크레딧 문자열)를 보고 판단하므로
패턴을 조금만 넓혀도 소속을 발견 주체로 오인한다. 실제로 'Kostya Kortchinsky | OpenAI'는
OpenAI 소속 사람 연구원이지 AI가 찾은 게 아니다 — 'openai' 같은 일반어를 넣는 순간
이런 건이 전부 AI 발견으로 둔갑한다.

아래 '오탐이면 안 되는 것' 목록이 그 계약이다.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import ai_provenance as ap  # noqa: E402

# 실제 cvelistV5 크레딧에서 그대로 가져온 문자열들 (2026-08 실측)
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

# 오탐이면 안 되는 것 — 전부 사람이거나 무관한 문자열이다
SHOULD_MISS = [
    ["Kostya Kortchinsky | OpenAI"],          # OpenAI 소속 '사람' 연구원
    ["George Chen"],
    ["WPScan"],
    ["Professor Le Yu of Nanjing University of Posts and Telecommunications"],
    ["reported by an AI enthusiast"],          # 일반어 'AI'로는 잡지 않는다
    ["Anthropic Inc. is not involved"],        # 'anthropic' 단독으로는 잡지 않는다
    ["automated fuzzing found this"],          # 자동 퍼징 ≠ AI 발견
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
