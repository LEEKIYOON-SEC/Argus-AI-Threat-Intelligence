#!/usr/bin/env python3
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

import risk

V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
ADJACENT = "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

TIER_CASES = [
    ("KEV + 랜섬웨어",        {"is_kev": True, "is_kev_ransomware": True,
                              "cvss": 9.8, "cvss_vector": V31}, risk.T0),
    ("VulnCheck KEV 단독",    {"is_vulncheck_kev": True, "cvss": 6.5}, risk.T0),
    ("SSVC active",          {"ssvc_exploitation": "active", "cvss": 5.0}, risk.T0),
    ("Metasploit 모듈",       {"has_metasploit_module": True, "cvss": 0}, risk.T0),
    ("nuclei 템플릿",         {"has_nuclei_template": True, "cvss": 7.5,
                              "cvss_vector": V31}, risk.T1),
    ("ExploitDB",            {"has_public_exploit": True, "cvss": 5.0}, risk.T1),
    ("EPSS p99",             {"epss_percentile": 0.994, "epss": 0.62, "cvss": 5.0}, risk.T1),
    ("EPSS p95 (점수 폴백)",   {"epss": 0.12, "cvss": 5.0}, risk.T2),
    ("고위험 CWE + 원격",      {"cvss": 6.1, "cvss_vector": V31, "cwe": ["CWE-502"]}, risk.T2),
    ("CVSS 9.8 + CWE 근거",   {"cvss": 9.8, "cvss_vector": V31, "cwe": ["CWE-502"]}, risk.T2),
    ("CVSS 9.8 + 주요 CNA",   {"cvss": 9.8, "cvss_vector": V31, "assigner": "microsoft"}, risk.T2),
    ("SSVC automatable",     {"ssvc_automatable": "yes", "cvss": 4.0}, risk.T2),
    ("SSVC total impact",    {"ssvc_technical_impact": "total", "cvss": 4.0}, risk.T2),
    ("무점수 + 주요 CNA",      {"cvss": 0, "assigner": "Fortinet"}, risk.T2),

    ("CVSS 9.8 단독(근거 없음)", {"cvss": 9.8, "cvss_vector": V31}, risk.T3),
    ("CVSS 10 단독(근거 없음)",  {"cvss": 10.0, "cvss_vector": V40}, risk.T3),
    ("CVSS 7.5 원격무인증",     {"cvss": 7.5, "cvss_vector": V31}, risk.T3),
    ("CVSS 9.8 로컬",         {"cvss": 9.8, "cvss_vector": LOCAL}, risk.T3),
    ("CVSS 9.8 인접(AV:A)",   {"cvss": 9.8, "cvss_vector": ADJACENT}, risk.T3),
    ("고위험 CWE + 로컬",      {"cvss": 6.1, "cvss_vector": LOCAL, "cwe": ["CWE-502"]}, risk.T3),
    ("무점수 + 무명 CNA",      {"cvss": 0, "assigner": "some-oss-project"}, risk.T3),
    ("벡터 없는 CVSS 9.8",     {"cvss": 9.8}, risk.T3),
    ("평범한 중위험",          {"cvss": 5.4, "cvss_vector": LOCAL}, risk.T3),
]


def check(cond, msg, failures):
    if not cond:
        failures.append(msg)
        print(f"  FAIL {msg}")
        return False
    return True


def main() -> int:
    failures = []

    print("── 티어 판정 ──")
    for name, state, want in TIER_CASES:
        got = risk.evaluate(state)
        if check(got.tier == want, f"{name}: {got.tier} (기대 {want})", failures):
            print(f"  OK   {name:24s} → {got.tier}  {sorted(got.triggers)}")

    print("\n── 전이 · 반복 발화 억제 ──")
    base = {"cvss": 7.5, "cvss_vector": V31, "cwe": ["CWE-502"]}
    d = risk.decide(base, None)
    check(not d.alert and d.tier == risk.T2, "신규 T2는 알리지 않아야 한다", failures)
    state = {"fired_triggers": risk.merge_fired(None, d.new_triggers)}

    kev = dict(base, is_kev=True)
    d = risk.decide(kev, state)
    check(d.alert and d.tier == risk.T0, "KEV 등재는 알려야 한다", failures)
    state = {"fired_triggers": risk.merge_fired(state, d.new_triggers)}

    check(not risk.decide(kev, state).alert, "같은 상태 재평가는 조용해야 한다", failures)

    surged = dict(kev, epss_percentile=0.995)
    d = risk.decide(surged, state)
    check(d.alert and d.new_triggers == frozenset({"epss_critical"}),
          "새로 켜진 트리거만 알려야 한다", failures)
    state = {"fired_triggers": risk.merge_fired(state, d.new_triggers)}

    check(not risk.decide(dict(surged, epss_percentile=0.999), state).alert,
          "EPSS가 더 올라도 재알림은 없어야 한다", failures)
    print("  OK   전이 4종 · 반복 발화 억제")

    print("\n── 전환 안전성 (fired_triggers 없는 과거 행) ──")
    legacy = {"is_kev": True, "cvss": 9.8, "cvss_vector": V31}
    check(not risk.decide(legacy, legacy).alert,
          "과거 행 재평가가 알림 폭풍을 내면 안 된다", failures)
    print("  OK   과거 행 재평가는 조용하다")

    print("\n── 벡터 파서 ──")
    check(risk.is_remote_unauth(V31) and risk.is_remote_unauth(V40),
          "3.1/4.0 모두 원격무인증으로 읽어야 한다", failures)
    check(not risk.is_remote_unauth(LOCAL), "로컬 벡터를 원격으로 읽으면 안 된다", failures)
    check(not risk.is_remote_unauth(None) and not risk.is_remote_unauth("N/A"),
          "벡터를 모르면 위험하다고 단정하지 않아야 한다", failures)
    check(risk.is_low_complexity(V31) and risk.is_low_complexity(V40),
          "AC:L(3.x)과 AT:N(4.0)을 같이 봐야 한다", failures)
    print("  OK   벡터 파서")

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
