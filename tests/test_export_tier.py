#!/usr/bin/env python3
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

if importlib.util.find_spec("supabase") is None:
    print("supabase 미설치 — 이 검사는 건너뜁니다 (pip install -r requirements.txt)")
    sys.exit(0)

for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")

_spec = importlib.util.spec_from_file_location(
    "export_dashboard_data", os.path.join(ROOT, "src", "export_dashboard_data.py"))
edd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(edd)

CASES = (
    ("KEV인데 tier 필드가 없는 과거 행",
     {"is_kev": True, "title": "x"}, {"is_kev": True, "cvss": 7.5, "epss": 0.01}, "T0"),
    ("KEV가 state엔 없고 컬럼에만 있는 행 (스칼라는 컬럼이 정본)",
     {"title": "x"}, {"is_kev": True, "cvss": 9.8, "epss": 0.0}, "T0"),

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

    ("신호 전무 — 예전엔 무조건 T2로 보였다", {"title": "x"},
     {"is_kev": False, "cvss": 5.0, "epss": 0.001}, "T3"),

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
    for key, want_max in (("is_kev", "T0"), ("has_metasploit_module", "T0"),
                          ("is_vulncheck_kev", "T0"), ("has_nuclei_template", "T1"),
                          ("has_public_exploit", "T1"), ("ai_discovered", "T1")):
        got = edd._tier_of({key: True}, {"is_kev": key == "is_kev", "cvss": 0, "epss": 0})
        ok = risk.tier_rank(got) <= risk.tier_rank(want_max)
        print(f"  {'OK  ' if ok else 'FAIL'} {key:24s} → {got} ({want_max} 이하)")
        if not ok:
            failures.append(key)

    retention_guard(failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


RETENTION_CASES = (
    # 소급 채우기(silent=True)는 last_alert_at 을 남기지 않는다. 보존 정책의 만료 삭제가
    # 바로 그 조건(last_alert_at IS NULL + 오래됨)을 쓰므로, 지금 악용 중인 T0 행이
    # 관찰 만료로 오인돼 지워질 수 있었다. 2015~2020년 KEV 는 레코드가 더는 안 바뀐다.
    ("소급으로 넣은 CISA KEV 행",
     {"id": "CVE-2015-7755", "is_kev": True, "cvss_score": 9.8, "epss_score": 0.3,
      "last_alert_state": {"tier": "T0", "is_kev": True}}, True),
    ("VulnCheck KEV 전용 행",
     {"id": "CVE-2019-1", "is_kev": False, "cvss_score": 7.5, "epss_score": 0.01,
      "last_alert_state": {"tier": "T0", "is_vulncheck_kev": True}}, True),
    ("Metasploit 모듈 (저장된 tier 없음)",
     {"id": "CVE-2018-1", "is_kev": False, "cvss_score": 8.0, "epss_score": 0.02,
      "last_alert_state": {"has_metasploit_module": True}}, True),
    ("nuclei 템플릿 (T1)",
     {"id": "CVE-2021-1", "is_kev": False, "cvss_score": 7.0, "epss_score": 0.0,
      "last_alert_state": {"has_nuclei_template": True}}, True),
    ("관찰 구간 (T2)",
     {"id": "CVE-2022-1", "is_kev": False, "cvss_score": 8.1, "epss_score": 0.12,
      "last_alert_state": {"tier": "T2", "epss_percentile": 0.96}}, False),
    ("신호 없음 (T3)",
     {"id": "CVE-2023-1", "is_kev": False, "cvss_score": 5.0, "epss_score": 0.001,
      "last_alert_state": {"tier": "T3"}}, False),
    ("이미 비워진 행",
     {"id": "CVE-2017-1", "is_kev": False, "cvss_score": 0, "epss_score": 0,
      "last_alert_state": None}, False),
)


def retention_guard(failures):
    print("\n── 보존 정책이 악용 중인 행을 지우지 않는다 ──")
    for desc, row, keep in RETENTION_CASES:
        got = edd._is_alerting_row(row)
        if got == keep:
            print(f"  OK   {desc:36s} → {'보존' if got else '삭제 가능'}")
        else:
            failures.append(desc)
            print(f"  FAIL {desc:36s} → {'보존' if got else '삭제 가능'} "
                  f"(기대 {'보존' if keep else '삭제 가능'})")


if __name__ == "__main__":
    sys.exit(main())
