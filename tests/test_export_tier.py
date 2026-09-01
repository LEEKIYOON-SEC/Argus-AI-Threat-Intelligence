#!/usr/bin/env python3
"""대시보드가 표시하는 티어가 판정과 어긋나지 않는지 — 회귀 테스트.

    python3 tests/test_export_tier.py

왜 이 테스트가 있나: 화면이 **CISA KEV에 올라 있는 CVE를 '관찰'로 표시했다.**

원인은 판정이 아니라 export의 한 줄이었다.

    entry["tier"] = _s(state, "tier") or "T2"      # ← 없으면 T2로 단정

tier는 2-lane 개편에서 새로 생긴 필드라 그 이전에 저장된 행에는 **전부 없다.** 그래서
그 행들이 신호와 무관하게 일괄 '관찰'로 보였다. 값이 없을 때 특정 티어로 단정한 것이
잘못이었지, 판정(risk.evaluate)은 멀쩡했다.

여기서 지키는 계약은 하나다 — **화면은 위험을 낮춰 부르지 않는다.**
저장값이 없으면 행이 가진 신호에서 유도하고, 저장값과 유도값이 어긋나면 더 위험한 쪽을 쓴다.
"""
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

# export 모듈은 supabase 클라이언트를 import 한다. 개발 환경에 없다고 게이트를 막지 않는다
# (워크플로는 requirements.txt 를 설치하므로 거기서는 반드시 돈다).
if importlib.util.find_spec("supabase") is None:
    print("supabase 미설치 — 이 검사는 건너뜁니다 (pip install -r requirements.txt)")
    sys.exit(0)

for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")

_spec = importlib.util.spec_from_file_location(
    "export_dashboard_data", os.path.join(ROOT, "src", "export_dashboard_data.py"))
edd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edd)

#: (설명, last_alert_state, 스칼라 컬럼, 기대 티어)
CASES = (
    # ── 사용자가 실제로 본 증상 ──
    ("KEV인데 tier 필드가 없는 과거 행",
     {"is_kev": True, "title": "x"}, {"is_kev": True, "cvss": 7.5, "epss": 0.01}, "T0"),
    ("KEV가 state엔 없고 컬럼에만 있는 행 (스칼라는 컬럼이 정본)",
     {"title": "x"}, {"is_kev": True, "cvss": 9.8, "epss": 0.0}, "T0"),

    # ── 나머지 알림 신호도 같은 방식으로 살아나야 한다 ──
    ("Metasploit 모듈", {"has_metasploit_module": True},
     {"is_kev": False, "cvss": 8.8, "epss": 0.02}, "T0"),
    ("SSVC Exploitation=active", {"ssvc_exploitation": "active"},
     {"is_kev": False, "cvss": 0, "epss": 0}, "T0"),
    ("nuclei 템플릿", {"has_nuclei_template": True},
     {"is_kev": False, "cvss": 7.5, "epss": 0.0}, "T1"),
    ("AI 발견", {"ai_discovered": True, "ai_program": "Google Big Sleep"},
     {"is_kev": False, "cvss": 0, "epss": 0}, "T1"),
    ("EPSS 상위 1% (p99)", {"epss_percentile": 0.995},
     {"is_kev": False, "cvss": 7.0, "epss": 0.6}, "T1"),

    # ── 신호가 없으면 '관찰'이 아니라 '신호 없음'이다 ──
    ("신호 전무 — 예전엔 무조건 T2로 보였다", {"title": "x"},
     {"is_kev": False, "cvss": 5.0, "epss": 0.001}, "T3"),

    # ── 저장값과 유도값이 어긋날 때 ──
    ("저장 T2인데 그 사이 KEV에 올라옴 → 더 위험한 쪽",
     {"tier": "T2", "is_kev": True}, {"is_kev": True, "cvss": 9.8, "epss": 0.3}, "T0"),
    ("저장 T0인데 state에 신호가 안 남음 → 저장값 유지",
     {"tier": "T0"}, {"is_kev": False, "cvss": 0, "epss": 0}, "T0"),
    ("저장값이 쓰레기면 무시하고 유도한다",
     {"tier": "높음", "is_kev": True}, {"is_kev": True, "cvss": 9.8, "epss": 0.3}, "T0"),
)


def main() -> int:
    failures = []
    print("── 저장된 tier가 없거나 어긋날 때 ──")
    for desc, state, entry, want in CASES:
        got = edd._tier_of(state, entry)
        if got == want:
            print(f"  OK   {desc:44s} → {got}")
        else:
            failures.append(desc)
            print(f"  FAIL {desc:44s} → {got} (기대 {want})")

    print("\n── 화면은 위험을 낮춰 부르지 않는다 ──")
    import risk
    # 알림이 나가는 신호를 하나라도 들고 있으면 T2 이하로 내려가면 안 된다
    for key, want_max in (("is_kev", "T0"), ("has_metasploit_module", "T0"),
                          ("is_vulncheck_kev", "T0"), ("has_nuclei_template", "T1"),
                          ("has_public_exploit", "T1"), ("ai_discovered", "T1")):
        got = edd._tier_of({key: True}, {"is_kev": key == "is_kev", "cvss": 0, "epss": 0})
        ok = risk.tier_rank(got) <= risk.tier_rank(want_max)
        print(f"  {'OK  ' if ok else 'FAIL'} {key:24s} → {got} ({want_max} 이하)")
        if not ok:
            failures.append(key)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
