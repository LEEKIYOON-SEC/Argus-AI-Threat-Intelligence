#!/usr/bin/env python3
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["ARGUS_CACHE_DIR"] = tempfile.mkdtemp()
for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")

import requests  # noqa: E402

import enrichment_sources as es  # noqa: E402
import pipeline  # noqa: E402
import risk  # noqa: E402
from collector import Collector  # noqa: E402

RECORD = {
    "cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED"},
    "containers": {"cna": {
        "descriptions": [{"lang": "en", "value": "Log4Shell"}],
        "title": "Log4Shell",
        "metrics": [{"cvssV3_1": {"baseScore": 10.0,
                                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}}],
    }},
}

STORED = {
    "id": "CVE-2021-44228", "is_kev": True, "is_vulncheck_kev": True,
    "is_kev_ransomware": True, "has_metasploit_module": True,
    "metasploit_modules": ["exploit/multi/http/log4shell"],
    "has_nuclei_template": True, "has_public_exploit": True, "has_poc": True,
    "epss": 0.94, "epss_percentile": 0.999, "tier": risk.T0,
    "fired_triggers": ["kev", "metasploit", "nuclei", "exploitdb", "epss_critical"],
    "cvss": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N",
    "references": ["https://vendor.example/advisory"],
}


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def main() -> int:
    failures = []
    real_get = requests.get

    def dead(*a, **k):
        raise requests.exceptions.ConnectionError("네트워크 끊김")

    print("── 신호원이 전부 실패한 회차 ──")
    requests.get = dead
    try:
        c = Collector()
        c.fetch_kev()
        c.fetch_vulncheck_kev()
        st = pipeline.build_state("CVE-2021-44228", RECORD, c, None)
    finally:
        requests.get = real_get

    check(not es.metasploit_ok(), "metasploit 인덱스를 '없음'이 아니라 '못 받음'으로 안다", failures)
    check(not es.nuclei_ok(), "nuclei 인덱스도 마찬가지", failures)
    check(not es.exploitdb_ok(), "exploitdb 인덱스도 마찬가지", failures)
    check(not c.kev_loaded, "KEV 도 마찬가지", failures)

    for key in ("is_kev", "is_vulncheck_kev", "has_metasploit_module",
                "has_nuclei_template", "has_public_exploit", "epss"):
        check(key not in st, f"{key} 를 False 로 덮어쓰지 않는다 (키 자체가 없다)", failures)

    check(risk.evaluate(st).tier == risk.T3, "이월 전에는 신호가 없어 T3", failures)

    print("\n── 이전에 알던 값을 이월한다 ──")
    pipeline.carry_forward(st, STORED)
    v = risk.evaluate(st)
    check(v.tier == risk.T0, f"등급이 유지된다 ({v.tier})", failures)
    for key in ("kev", "vulncheck_kev", "metasploit", "nuclei", "exploitdb"):
        check(key in v.triggers, f"{key} 트리거가 살아 있다", failures)
    check(st["epss"] == 0.94, f"EPSS 도 유지 ({st['epss']})", failures)
    check(st["references"] == [], "레코드를 읽었으면 그 결과를 따른다 (references 는 원문에 없음)",
          failures)

    print("\n── 저장 페이로드에도 그대로 담긴다 ──")
    clean = {k: st[k] for k in pipeline.STATE_FIELDS if k in st}
    for key in ("is_kev", "has_metasploit_module", "has_nuclei_template", "epss"):
        check(clean.get(key) == STORED[key], f"{key} = {clean.get(key)}", failures)

    print("\n── 이번 회차가 관측한 값은 이월이 덮지 않는다 ──")
    fresh = {"id": "X", "is_kev": False, "has_nuclei_template": False}
    pipeline.carry_forward(fresh, {"is_kev": True, "has_nuclei_template": True,
                                   "has_metasploit_module": True})
    check(fresh["is_kev"] is False, "관측된 False 는 그대로 False", failures)
    check(fresh["has_nuclei_template"] is False, "관측된 False 는 그대로 False", failures)
    check(fresh["has_metasploit_module"] is True, "관측 못 한 것만 이월", failures)

    print("\n── last 가 없거나 깨져도 안 터진다 ──")
    for desc, last in (("None", None), ("빈 dict", {}), ("dict 아님", "x"), ("리스트", [])):
        try:
            out = pipeline.carry_forward({"id": "Y"}, last)
            check(out == {"id": "Y"}, f"{desc} → 그대로", failures)
        except Exception as e:
            check(False, f"{desc} → {type(e).__name__}: {e}", failures)

    print("\n── 신호원이 살아 있으면 정상 관측한다 ──")
    es._msf_index.clear()
    es._nuclei_index.clear()
    es._exploitdb_index.clear()
    es._msf_loaded = es._nuclei_loaded = es._exploitdb_loaded = True
    es._nuclei_ok = es._exploitdb_ok = False
    es._msf_index["CVE-2021-44228"] = [{"fullname": "exploit/x", "rank": 600,
                                        "rank_name": "excellent", "type": "exploit"}]
    es._msf_ok = True
    c2 = Collector()
    c2.kev_loaded = True
    c2.kev_set = {"CVE-2021-44228"}
    data = {"id": "CVE-2021-44228", "credits": [], "affected": []}
    c2.enrich_cheap_signals(data)
    check(data.get("has_metasploit_module") is True,
          "인덱스가 있으면 True 로 관측된다", failures)
    check("has_nuclei_template" not in data,
          "여전히 못 받은 소스는 키를 안 만든다", failures)

    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
