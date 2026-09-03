#!/usr/bin/env python3
"""전수 검토에서 나온 고장들 — 다시 생기지 않게 잡아 두는 검사.

    python3 tests/test_audit_fixes.py

전부 실제로 운영 중이던 버그다. 하나씩 어떻게 드러났는지 적어 둔다.
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

import risk  # noqa: E402
from backfill_signals import reconcile  # noqa: E402
from collector import Collector, _clip, flatten_ssvc  # noqa: E402


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def rec(ssvc_options):
    """CISA-ADP 컨테이너가 SSVC 를 주는 실제 모양."""
    return {
        "cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED"},
        "containers": {
            "cna": {"descriptions": [{"lang": "en", "value": "x"}], "title": "T"},
            "adp": [{
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [{"other": {"type": "ssvc",
                                       "content": {"options": ssvc_options}}}],
            }],
        },
    }


def main() -> int:
    failures = []

    print("── ① SSVC 가 판정까지 도달한다 ──")
    # 고장: collector 는 data['ssvc']['exploitation'] 에 넣는데 risk.evaluate 는
    # state['ssvc_exploitation'] 만 읽었다. 트리거 3개가 통째로 죽어 있었다.
    # 실측(배포본 13,275행): ssvc_active 439 · automatable 1,647 · total_impact 3,699.
    c = Collector()
    data = c.parse_record("CVE-2026-0001", rec([{"Exploitation": "active"},
                                                {"Automatable": "yes"},
                                                {"Technical Impact": "total"}]))
    check(data.get("ssvc_exploitation") == "active",
          f"ssvc_exploitation 이 평탄한 키로 온다 ({data.get('ssvc_exploitation')!r})", failures)
    check(data.get("ssvc_automatable") == "yes", "ssvc_automatable", failures)
    check(data.get("ssvc_technical_impact") == "total", "ssvc_technical_impact", failures)
    check(data.get("ssvc", {}).get("exploitation") == "active",
          "중첩본도 그대로 남는다 (화면·리포트가 그걸 본다)", failures)

    v = risk.evaluate(data)
    check("ssvc_active" in v.triggers, f"ssvc_active 가 발화한다 ({sorted(v.triggers)})", failures)
    check(v.tier == risk.T0, f"등급이 T0 가 된다 ({v.tier})", failures)

    print("\n  ── 값이 없거나 깨져도 안 터진다 ──")
    for desc, arg in (("ssvc 가 None", {"ssvc": None}), ("ssvc 가 문자열", {"ssvc": "x"}),
                      ("빈 dict", {"ssvc": {}}), ("값이 빈 문자열", {"ssvc": {"exploitation": " "}}),
                      ("값이 숫자", {"ssvc": {"exploitation": 3}})):
        try:
            out = flatten_ssvc(dict(arg))
            check("ssvc_exploitation" not in out, f"{desc} → 평탄 키를 안 만든다", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)

    print("\n── ② SSVC 복구가 알림 폭풍을 내지 않는다 ──")
    # 평탄화만 하고 두면, 그 CVE 가 다음에 한 번 바뀌는 순간 risk.decide 가
    # ssvc_active(T0)를 '처음 보는 신호'로 읽고 Slack 을 쏜다. 439건이 순차로 터진다.
    old = {"id": "CVE-2016-0001", "ssvc": {"exploitation": "active"},
           "tier": risk.T3, "fired_triggers": []}
    fixed = reconcile(old)
    check(fixed["tier"] == risk.T0, f"등급이 T0 로 정정된다 ({fixed['tier']})", failures)
    check("ssvc_active" in fixed["fired_triggers"],
          f"발화 이력에 미리 채운다 ({fixed['fired_triggers']})", failures)
    decision = risk.decide(fixed, fixed)
    check(not decision.alert, "그래서 다음 회차에 알림이 안 나간다", failures)

    before = risk.decide(flatten_ssvc(dict(old)), old)
    check(before.alert, "정합을 안 돌리면 알림이 나갔을 것이다 (이 도구가 막는 것)", failures)

    print("\n  ── 이미 있는 발화 이력을 지우지 않는다 ──")
    keep = reconcile({"id": "X", "is_kev": True, "tier": risk.T0,
                      "fired_triggers": ["kev", "nuclei"]})
    check(set(keep["fired_triggers"]) >= {"kev", "nuclei"},
          f"기존 이력이 남는다 ({keep['fired_triggers']})", failures)

    print("\n  ── 손댈 게 없는 행은 그대로 둔다 ──")
    same = {"id": "Y", "tier": risk.T3, "fired_triggers": [], "cvss": 5.0}
    check(reconcile(same) == same, "변화 없음 → 저장 대상이 아니다", failures)

    print("\n── ③ 제목이 단어 중간에서 안 잘린다 ──")
    # 실제: CVE-2016-0193 의 제목이 '…or cause a de' 로 끊겨 화면에 그대로 나왔다.
    long = ("The Chakra JavaScript engine in Microsoft Edge allows remote attackers to "
            "execute arbitrary code or cause a denial of service")
    out = _clip(long, 110)
    check(len(out) <= 111, f"길이 상한을 지킨다 ({len(out)}자)", failures)
    check(not out.rstrip("…").endswith("de"), f"단어 중간에서 안 끊긴다 → …{out[-24:]!r}", failures)
    check(out.endswith("…"), "잘렸다는 표시가 붙는다", failures)
    check(_clip("짧다", 110) == "짧다", "짧으면 그대로", failures)
    check(_clip("", 110) == "", "빈 문자열도 안전", failures)
    check(_clip("a" * 200, 110).startswith("a"), "공백이 없는 문자열도 자른다", failures)

    print("\n── ④ 저장되는 필드에 references 가 있다 ──")
    # 고장: 수집은 하는데 STATE_FIELDS 에 없어서 저장이 안 됐다. 알림 시점에는 신선한
    # state 를 쓰니 '벤더 권고' 버튼이 나왔지만, 리포트 보강이 저장된 state 로 다시
    # 만들면 참고 자료가 통째로 비었고 analyzer 입력에서도 사라졌다.
    import pipeline
    for key in ("references", "cvss_version", "cvss_scores", "assigner",
                "ssvc_exploitation", "ssvc_automatable", "ssvc_technical_impact"):
        check(key in pipeline.STATE_FIELDS, f"STATE_FIELDS 에 {key}", failures)

    print("\n── ⑤ export 가 nuclei·splunk 룰을 안 버린다 ──")
    import export_dashboard_data as ex
    for key in ("sigma", "nuclei", "splunk", "yara"):
        check(key in ex._SINGLE_RULE_KEYS, f"{key} 를 싣는다", failures)

    print("\n  ── export 의 등급 계산도 SSVC 를 본다 ──")
    state = {"ssvc": {"exploitation": "active"}, "tier": risk.T3}
    check(ex._tier_of(state, {"is_kev": False, "cvss": 0, "epss": 0}) == risk.T0,
          "중첩본만 있는 옛 행도 T0 로 읽는다", failures)

    print("\n── ⑥ 번역 창이 소화한 만큼만 전진한다 ──")
    # 고장: 한도 24건에서 멈춰 놓고 offset 을 창 크기 200 만큼 밀었다. 한 창에 영문이
    # 24건을 넘으면 나머지는 offset 이 지나가 버렸다 — 실측 미번역 2,340건 중
    # 1,447건이 구조적으로 도달 불가였다.
    src = open(os.path.join(ROOT, "src", "main.py"), encoding="utf-8").read()
    body = src[src.index("def translate_tracked"):src.index("def _translation_exhausted")]
    check("next_offset = offset + scanned" in body,
          "전진 폭이 실제 스캔량(scanned)이다", failures)
    check("offset + pool" not in body, "창 크기(pool)로 밀지 않는다", failures)
    # 후보가 비면 offset 을 쓰지 않고 빠져나간다 — 조회 실패를 '끝'으로 읽으면
    # 순회가 처음으로 되감기고 뒤쪽 행은 영영 안 온다.
    empty = re.search(r"if not candidates:\s*\n(?:.*\n)*?\s*break\b", body)
    check(empty is not None, "후보가 비면 빠져나간다", failures)
    check(empty is not None and "write_backfill_offset" not in empty.group(),
          "그 경로에서 offset 을 건드리지 않는다 (조회 실패 ≠ 끝)", failures)

    print("\n── ⑦ fast-lane 이 처리한 건을 실패로 세지 않는다 ──")
    # 고장: changes[len(outcomes):] 로 끊었는데 record 없는 건은 outcomes 에 안 담겨
    # 인덱스가 밀렸다. 이미 알림까지 나간 CVE 가 실패로 기록되고, 3회 쌓이면 격리됐다.
    fl = open(os.path.join(ROOT, "src", "fast_lane.py"), encoding="utf-8").read()
    check("for i, change in enumerate(changes)" in fl, "인덱스로 순회한다", failures)
    check("changes[len(outcomes):]" not in fl, "len(outcomes) 로 끊지 않는다", failures)

    print("\n── ⑧ 죽은 코드가 다시 안 들어온다 ──")
    col = open(os.path.join(ROOT, "src", "collector.py"), encoding="utf-8").read()
    for gone in ("def enrich_threat_intel", "def enrich_from_nvd", "def check_poc_exists",
                 "def enrich_cve", "def fetch_epss", "class CollectorError"):
        check(gone not in col, f"{gone} 가 없다", failures)
    check(len(col.splitlines()) < 500,
          f"collector.py 가 {len(col.splitlines())}줄 (전 702줄)", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
