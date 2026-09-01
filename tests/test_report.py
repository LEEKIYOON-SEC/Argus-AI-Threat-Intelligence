#!/usr/bin/env python3
"""리포트 본문 — 알림 시점의 상태로도 만들어지는지.

    python3 tests/test_report.py

왜 있나: 실행 로그에 이게 찍혔다.

    [ERROR] GitHub Issue 생성 실패: 'title_ko'
    [INFO] Slack 즉시 알림: CVE-2026-5027 [T0] ...

`report.py` 가 `cve_data['title_ko']` 를 직접 꺼냈는데, **알림 시점의 상태에는 그 키가
없다** — 번역은 bulk-lane 이 나중에 채운다. KeyError 를 create_github_issue 의 except 가
삼켜서 한 줄 로그로만 보였고, 알림은 리포트 링크 없이 나갔다.

한 시간 뒤 리포트 보강(backfill_reports)에서는 성공했는데, 거기서만 setdefault 로
title_ko·references·cvss 를 메우고 있었기 때문이다. 즉 **호출 경로마다 필요한 키가
다르다**는 사실을 한쪽만 알고 있었다. 그래서 report.py 쪽에서 가정을 없앴다.

여기서 지키는 계약: 리포트 본문은 **id 하나만 있어도** 만들어진다. 없는 값은 폴백한다.
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

if importlib.util.find_spec("google.genai") is None:
    print("google-genai 미설치 — 이 검사는 건너뜁니다 (pip install -r requirements.txt)")
    sys.exit(0)

for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")

import report  # noqa: E402

ANALYSIS = {"summary": "요약", "root_cause": "원인", "attack_scenario": "시나리오",
            "impact": "영향", "mitigation": ["패치 적용"], "detection": "탐지"}

# 알림 시점(fast-lane / 스냅샷 대조)이 넘기는 상태 — pipeline.build_state 의 출력 모양.
# title 은 있고 title_ko 는 없다.
AT_ALERT = {
    "id": "CVE-2026-5027", "title": "Langflow - Path Traversal",
    "description": "A path traversal issue…", "cvss": 9.8, "epss": 0.42,
    "is_kev": True, "cwe": ["CWE-22"], "references": ["https://example.com/a"],
    "affected": [{"vendor": "Langflow", "product": "Langflow", "versions": "1.0 이전"}],
    "has_nuclei_template": True, "fired_triggers": ["kev", "nuclei"],
}


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    failures = []

    print("── 알림 시점 상태 (title_ko 없음) ──")
    check("title_ko" not in AT_ALERT, "표본에 title_ko 가 없다 (실제 상황과 같다)", failures)
    try:
        body = report._build_issue_body(AT_ALERT, "사유", ANALYSIS, {})
        check(len(body) > 500, f"본문이 만들어진다 ({len(body):,}자)", failures)
        check("Langflow - Path Traversal" in body.splitlines()[0],
              "제목이 영문 title 로 폴백된다", failures)
    except Exception as e:
        check(False, f"본문 생성이 터진다: {type(e).__name__}: {e}", failures)

    print("\n── 없는 값이 있어도 안 터진다 ──")
    for desc, data in (
        ("id 하나만", {"id": "CVE-0000-0001"}),
        ("references 없음", {"id": "X", "title": "T", "cvss": 7.0}),
        ("cwe 가 None", {"id": "X", "title": "T", "cwe": None}),
        ("affected 항목에 키가 빔", {"id": "X", "title": "T", "affected": [{"vendor": "V"}]}),
        ("cvss/epss 가 None", {"id": "X", "title": "T", "cvss": None, "epss": None}),
    ):
        try:
            b = report._build_issue_body(data, "사유", ANALYSIS, {})
            check(bool(b), f"{desc} → {len(b):,}자", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)

    print("\n── 분석·룰이 비어도 안 터진다 ──")
    for desc, an, rl in (("analysis=None", None, {}), ("rules=None", ANALYSIS, None),
                         ("둘 다 None", None, None)):
        try:
            b = report._build_issue_body(AT_ALERT, "사유", an, rl)
            check(bool(b), f"{desc} → {len(b):,}자", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)

    print("\n── CVSS 버전 표기 ──")
    # 4.0 과 3.x 는 산식이 달라 실측 22%가 두 버전을 갖고 대부분 점수가 다르다.
    # 어느 버전인지 안 밝히면 NVD 에서 다른 값을 본 사람이 무엇이 맞는지 알 수 없다.
    body = report._build_issue_body(dict(AT_ALERT, cvss_version="3.1"), "사유", ANALYSIS, {})
    check("CVSS%20v3.1" in body, "배지에 버전이 붙는다 (v3.1)", failures)
    body = report._build_issue_body(AT_ALERT, "사유", ANALYSIS, {})
    check("badge/CVSS-" in body, "버전을 모르면 그냥 CVSS 로 (안 터진다)", failures)

    print("\n── 제목 폴백 순서 ──")
    cases = (({"id": "X", "title": "En", "title_ko": "한글"}, "한글", "번역본이 있으면 그걸"),
             ({"id": "X", "title": "En"}, "En", "번역 전이면 영문 원문"),
             ({"id": "X", "title": "", "title_ko": "  "}, "X", "둘 다 비면 CVE ID"),
             ({"id": "X", "title_ko": None}, "X", "None 도 안전하게"))
    for data, want, desc in cases:
        got = report._display_title(data)
        check(got == want, f"{desc} → {got!r}", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
