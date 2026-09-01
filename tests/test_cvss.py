#!/usr/bin/env python3
"""CVSS 버전 처리 — 4.0 만 보고 3.x 를 버리지 않는지.

    python3 tests/test_cvss.py

왜 있나: 예전 코드는 metrics 를 돌며 4.0 을 만나면 바로 break 했다.

    for metric in cna.get('metrics', []):
        if 'cvssV4_0' in metric:  ...  break
        elif 'cvssV3_1' in metric: ... break

그런데 4.0 과 3.x 는 산식이 달라 점수가 자주 어긋난다 — 실측(203건) **22%가 두 버전을
갖고 있고 그중 대부분이 값이 다르다.**

    CVE-2026-82703   4.0=5.1  3.1=6.6
    CVE-2026-82954   4.0=9.4  3.1=9.9
    CVE-2026-82914   4.0=6.9  3.1=7.3

화면에는 어느 버전인지 표시도 없었다. NVD 에서 9.9 를 본 사람이 우리 화면의 9.4 를
보면 무엇이 맞는지 알 수가 없다.

지금은 전 버전을 모아 두고 **가장 높은 점수**를 판정에 쓴다(위험을 낮춰 부르지
않는다는 원칙 그대로). 화면·리포트·Slack 에는 버전을 함께 적고 다른 버전 점수도 보인다.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from collector import collect_cvss, pick_cvss  # noqa: E402


def m(**kw):
    return {k: {"baseScore": v[0], "vectorString": v[1]} for k, v in kw.items()}


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    failures = []

    print("── 전 버전을 모은다 ──")
    cna = {"metrics": [m(cvssV4_0=(9.4, "CVSS:4.0/AV:N")),
                       m(cvssV3_1=(9.9, "CVSS:3.1/AV:N"))]}
    got = collect_cvss([cna])
    check(set(got) == {"4.0", "3.1"}, f"4.0 과 3.1 을 둘 다 담는다 ({sorted(got)})", failures)
    check(got["3.1"][0] == 9.9, "3.1 점수가 보존된다", failures)

    print("\n── 가장 높은 점수를 쓴다 (위험을 낮춰 부르지 않는다) ──")
    cases = (
        ("4.0=9.4 · 3.1=9.9  (실제 CVE-2026-82954)",
         {"4.0": (9.4, "v4"), "3.1": (9.9, "v3")}, 9.9, "3.1"),
        ("4.0=5.1 · 3.1=6.6  (실제 CVE-2026-82703)",
         {"4.0": (5.1, "v4"), "3.1": (6.6, "v3")}, 6.6, "3.1"),
        ("4.0 이 더 높으면 4.0",
         {"4.0": (5.3, "v4"), "3.1": (4.3, "v3")}, 5.3, "4.0"),
        ("같으면 최신 버전",
         {"4.0": (7.5, "v4"), "3.1": (7.5, "v3")}, 7.5, "4.0"),
        ("3.x 만 있으면 그걸", {"3.1": (9.8, "v3")}, 9.8, "3.1"),
        ("4.0 만 있으면 그걸", {"4.0": (8.7, "v4")}, 8.7, "4.0"),
    )
    for desc, found, want_score, want_ver in cases:
        score, vector, ver = pick_cvss(found)
        ok = score == want_score and ver == want_ver
        check(ok, f"{desc} → {score} (v{ver})", failures)

    print("\n── 벡터는 채택한 버전의 것을 쓴다 ──")
    score, vector, ver = pick_cvss({"4.0": (9.4, "CVSS:4.0/X"), "3.1": (9.9, "CVSS:3.1/Y")})
    check(vector == "CVSS:3.1/Y", f"3.1 을 골랐으면 3.1 벡터 ({vector})", failures)

    print("\n── 껍데기만 있는 블록은 건너뛴다 ──")
    # 예전 코드가 죽던 모양: 첫 항목이 4.0 인데 baseScore 가 없다 → break 하고 3.1 을 못 봤다
    cna = {"metrics": [{"cvssV4_0": {"vectorString": "CVSS:4.0/AV:N"}},
                       m(cvssV3_1=(9.8, "CVSS:3.1/AV:N"))]}
    got = collect_cvss([cna])
    score, vector, ver = pick_cvss(got)
    check(score == 9.8 and ver == "3.1",
          f"baseScore 없는 4.0 을 건너뛰고 3.1=9.8 을 쓴다 ({score} v{ver})", failures)

    print("\n── CNA + ADP 를 합친다 ──")
    cna = {"metrics": [m(cvssV4_0=(8.7, "v4"))]}
    adp = {"metrics": [m(cvssV3_1=(9.8, "v3"))]}
    merged = collect_cvss([cna, adp])
    score, _, ver = pick_cvss(merged)
    check(score == 9.8 and ver == "3.1",
          f"CNA 가 4.0 만 내도 ADP 의 3.1 을 살린다 ({score} v{ver})", failures)

    print("\n── 깨진 입력 ──")
    for desc, arg in (("빈 목록", []), ("None 섞임", [None]),
                      ("metrics 가 None", [{"metrics": None}]),
                      ("점수가 문자열", [{"metrics": [{"cvssV3_1": {"baseScore": "높음"}}]}])):
        try:
            check(collect_cvss(arg) == {}, f"{desc} → 빈 결과", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)
    check(pick_cvss({}) == (0.0, "N/A", ""), "아무것도 없으면 0.0 / N/A", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
