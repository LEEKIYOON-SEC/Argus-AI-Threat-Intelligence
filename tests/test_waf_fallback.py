#!/usr/bin/env python3
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
for _k in ("SUPABASE_URL", "SUPABASE_KEY"):
    os.environ.setdefault(_k, "test")

import pipeline  # noqa: E402
import risk  # noqa: E402
from database import ArgusDB  # noqa: E402

STATE = {
    "id": "CVE-2021-44228",
    "title": "Apache Log4j2 JNDI ../../../etc/passwd RCE",
    "title_ko": "아파치 Log4j2 원격 코드 실행",
    "description": "An attacker can send ${jndi:ldap://x/a} and read /etc/passwd. "
                   "<script>alert(1)</script> UNION SELECT * FROM users. " + "긴 본문. " * 200,
    "desc_ko": "공격자가 JNDI 조회를 유발해 원격 코드를 실행할 수 있습니다. " * 40,
    "cwe": ["CWE-502", "CWE-917"],
    "affected": [{"vendor": "Apache", "product": "Log4j", "versions": "2.15.0 이전"}],
    "published": "2021-12-10",
    "cvss": 10.0,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_version": "3.1",
    "cvss_scores": {"3.1": [10.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"],
                    "2.0": [9.3, "AV:N/AC:M/Au:N/C:C/I:C/A:C"]},
    "epss": 0.97, "epss_percentile": 0.9999,
    "is_kev": True, "is_kev_ransomware": True, "kev_due_date": "2021-12-24",
    "is_vulncheck_kev": True,
    "ssvc": {"exploitation": "active", "automatable": "yes", "technical_impact": "total"},
    "ssvc_exploitation": "active", "ssvc_automatable": "yes",
    "ssvc_technical_impact": "total",
    "has_poc": True, "poc_urls": ["https://github.com/a/b", "https://github.com/c/d"],
    "has_public_exploit": True, "_exploit_db_url": "https://exploit-db.com/exploits/50592",
    "has_metasploit_module": True,
    "metasploit_modules": ["exploit/multi/http/log4shell_header_injection"],
    "has_nuclei_template": True, "nuclei_severity": "critical",
    "_nuclei_url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/x.yaml",
    "ai_discovered": True, "ai_program": "Anthropic CVD",
    "ai_detail": "Claude 가 발견", "ai_url": "https://red.anthropic.com/ledger",
    "assigner": "apache",
    "references": ["https://logging.apache.org/adv", "https://nvd.nist.gov/vuln/CVE-2021-44228"],
    "tier": risk.T0,
    "fired_triggers": ["kev", "metasploit", "nuclei", "exploitdb", "ssvc_active"],
}

PAYLOAD = {"id": "CVE-2021-44228", "cvss_score": 10.0, "epss_score": 0.97,
           "is_kev": True, "last_alert_state": dict(STATE),
           "updated_at": "2026-09-03T00:00:00+09:00",
           "report_url": "https://github.com/x/issues/1"}

RECOVERABLE = {"description", "title", "references", "poc_urls",
               "_exploit_db_url", "_nuclei_url", "ai_detail", "ai_url"}


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def _lost(state):
    return sorted(k for k in pipeline.STATE_FIELDS
                  if k in STATE and k not in state)


def main() -> int:
    failures = []

    print("── 2단계: 무력화본 ──")
    st2 = ArgusDB._waf_neutralized_copy(PAYLOAD)["last_alert_state"]
    check(_lost(st2) == [], f"필드를 하나도 잃지 않는다 (잃음: {_lost(st2)})", failures)
    check("​" in st2["description"], "위험 문자열은 ZWSP 로 무력화한다", failures)

    print("\n── 3단계: 축소본 ──")
    st3 = ArgusDB._waf_minimal_copy(PAYLOAD)["last_alert_state"]
    lost3 = _lost(st3)
    check(lost3 == [], f"축소본도 필드를 잃지 않는다 (잃음: {lost3})", failures)

    for key in ("cvss_vector", "cvss_version", "cvss_scores", "ssvc", "kev_due_date",
                "affected", "references", "poc_urls", "metasploit_modules",
                "nuclei_severity", "ai_program", "ai_url", "assigner",
                "_exploit_db_url", "_nuclei_url"):
        check(st3.get(key) == STATE[key], f"{key} 가 그대로 남는다", failures)

    check(len(st3["description"]) <= 300, f"본문은 줄인다 ({len(st3['description'])}자)",
          failures)
    check(len(st3["desc_ko"]) <= 300, f"번역 본문도 줄인다 ({len(st3['desc_ko'])}자)",
          failures)
    check(st3.get("waf_degraded") is True, "축소본임을 표시한다", failures)
    check("​" in st3["affected"][0]["product"] or st3["affected"][0]["product"],
          "제품명도 무력화 대상에 든다", failures)

    verdict = risk.evaluate(st3)
    check(verdict.tier == risk.T0, f"등급이 유지된다 ({verdict.tier})", failures)
    base = risk.evaluate(STATE)
    check(base.triggers - verdict.triggers == set(),
          f"트리거를 하나도 잃지 않는다 (잃음: {sorted(base.triggers - verdict.triggers)})",
          failures)

    print("\n── 4단계: 본문 제거본 (최후) ──")
    st4 = ArgusDB._waf_text_stripped_copy(PAYLOAD)["last_alert_state"]
    lost4 = set(_lost(st4))
    check(lost4 <= RECOVERABLE,
          f"버리는 것은 레코드에서 다시 읽어올 수 있는 것뿐 "
          f"(회복 불가한 것을 버림: {sorted(lost4 - RECOVERABLE)})", failures)
    check("title_ko" in st4 and "desc_ko" in st4,
          "번역은 남긴다 — API 한도를 써서 만든 것이라 다시 만들기 비싸다", failures)
    v4 = risk.evaluate(st4)
    check(v4.tier == risk.T0, f"최후 수단에서도 등급이 유지된다 ({v4.tier})", failures)
    check(base.triggers - v4.triggers == set(),
          f"트리거도 유지 (잃음: {sorted(base.triggers - v4.triggers)})", failures)

    print("\n── 단계가 갈수록 실제로 작아지는가 ──")
    import json
    sizes = [len(json.dumps(c(PAYLOAD), ensure_ascii=False)) for c in
             (lambda d: d, ArgusDB._waf_neutralized_copy, ArgusDB._waf_minimal_copy,
              ArgusDB._waf_text_stripped_copy)]
    print(f"    원본 {sizes[0]:,} → 무력화 {sizes[1]:,} → 축소 {sizes[2]:,} "
          f"→ 본문제거 {sizes[3]:,}")
    check(sizes[2] < sizes[1], "축소본이 무력화본보다 작다", failures)
    check(sizes[3] < sizes[2], "본문제거본이 축소본보다 작다", failures)

    print("\n── 원본을 건드리지 않는다 ──")
    check(PAYLOAD["last_alert_state"]["description"] == STATE["description"],
          "복사본을 만들지 원본을 수정하지 않는다", failures)
    check(len(PAYLOAD["last_alert_state"]["references"]) == 2, "목록도 그대로", failures)

    print("\n── 상태가 없거나 깨져도 안 터진다 ──")
    for desc, bad in (("state 없음", {"id": "X"}),
                      ("state 가 None", {"id": "X", "last_alert_state": None}),
                      ("state 가 문자열", {"id": "X", "last_alert_state": "x"})):
        try:
            ArgusDB._waf_minimal_copy(bad)
            ArgusDB._waf_text_stripped_copy(bad)
            check(True, f"{desc} → 통과", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
