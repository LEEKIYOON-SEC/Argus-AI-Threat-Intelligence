#!/usr/bin/env python3
import copy
import os
import sys
import tempfile

if not os.environ.get("ARGUS_TEST_NETWORK"):
    print("생략 — 이 테스트는 KEV·EPSS·VulnCheck 를 실제로 내려받는다. "
          "5분 레인에서 매번 돌리면 하루 288회 상류를 두드리고 알림이 그만큼 늦는다. "
          "ARGUS_TEST_NETWORK=1 로 돌린다 (주간 유지보수 잡이 그렇게 돌린다).")
    sys.exit(0)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["ARGUS_CACHE_DIR"] = tempfile.mkdtemp()
for k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(k, "test")

import requests  # noqa: E402

import enrichment_sources as es  # noqa: E402
import pipeline  # noqa: E402
import risk  # noqa: E402
from collector import Collector  # noqa: E402

RECORD = {
    "cveMetadata": {"cveId": "CVE-2021-44228", "state": "PUBLISHED",
                    "assignerShortName": "apache"},
    "containers": {"cna": {
        "title": "Log4Shell",
        "descriptions": [{"lang": "en", "value": "RCE via JNDI"}],
        "metrics": [{"cvssV3_1": {"baseScore": 10.0,
                                  "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}],
        "problemTypes": [{"descriptions": [{"cweId": "CWE-502"}]}],
        "references": [{"url": "https://logging.apache.org/adv"}],
        "affected": [{"vendor": "Apache", "product": "Log4j",
                      "versions": [{"status": "affected", "version": "2.0", "lessThan": "2.15.0"}]}],
    }},
}

GOOD = {
    "id": "CVE-2021-44228", "is_kev": True, "is_kev_ransomware": True,
    "is_vulncheck_kev": True, "has_metasploit_module": True,
    "metasploit_modules": ["exploit/x"], "has_nuclei_template": True,
    "has_public_exploit": True, "has_poc": True, "poc_urls": ["https://github.com/x"],
    "ssvc": {"exploitation": "active", "automatable": "yes", "technical_impact": "total"},
    "ssvc_exploitation": "active", "ssvc_automatable": "yes",
    "ssvc_technical_impact": "total",
    "epss": 0.97, "epss_percentile": 0.999,
    "cvss": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    "cvss_version": "3.1", "cvss_scores": {"3.1": [10.0, "CVSS:3.1/AV:N"]},
    "title_ko": "로그4셸", "desc_ko": "원격 코드 실행",
    "affected": [{"vendor": "Apache", "product": "Log4j", "versions": "2.15.0 이전"}],
    "references": ["https://logging.apache.org/adv"],
    "tier": risk.T0, "fired_triggers": ["kev", "metasploit", "nuclei", "exploitdb",
                                        "epss_critical", "ssvc_active"],
}

FAULTS = {
    "정상 (대조군)": set(),
    "KEV 만 실패": {"cisa"},
    "VulnCheck 만 실패": {"vulncheck"},
    "Metasploit 만 실패": {"metasploit"},
    "nuclei 만 실패": {"nuclei"},
    "ExploitDB 만 실패": {"exploitdb"},
    "PoC 인덱스만 실패": {"poc"},
    "EPSS 만 실패": {"epss"},
    "전부 실패": {"cisa", "vulncheck", "metasploit", "nuclei", "exploitdb", "poc", "epss"},
}

MARK = {
    "cisa": "cisa.gov", "vulncheck": "vulncheck.com",
    "metasploit": "metasploit-framework", "nuclei": "nuclei-templates",
    "exploitdb": "exploitdb", "poc": "PoC-in-GitHub", "epss": "epss",
}

CACHE = {
    "cisa": "cisa-kev.json", "vulncheck": "vulncheck-kev.bin",
    "metasploit": "metasploit-modules.json", "nuclei": "nuclei-cves.json",
    "exploitdb": "exploitdb-files.csv", "poc": "poc-in-github.md",
    "epss": "epss-full.csv.gz",
}


def run(fault):
    for mod in ("_exploitdb", "_msf", "_nuclei", "_poc"):
        setattr(es, f"{mod}_loaded", False)
        setattr(es, f"{mod}_ok", False)
        getattr(es, f"{mod}_index").clear()
    for key in fault:
        try:
            os.remove(os.path.join(os.environ["ARGUS_CACHE_DIR"], CACHE[key]))
        except OSError:
            pass
    real = requests.get

    def gated(url, *a, **k):
        for key in fault:
            if MARK[key] in str(url):
                raise requests.exceptions.ConnectionError("차단")
        return real(url, *a, **k)

    requests.get = gated
    try:
        c = Collector()
        c.fetch_kev()
        c.fetch_vulncheck_kev()
        epss = es.load_epss_above(risk.EPSS_P_HIGH)
        st = pipeline.build_state("CVE-2021-44228", RECORD, c, epss)
    finally:
        requests.get = real
    pipeline.carry_forward(st, copy.deepcopy(GOOD))
    saved = {k: st[k] for k in pipeline.STATE_FIELDS if k in st}
    return risk.evaluate(st), saved


base_v, base_saved = run(set())
print(f"{'주입한 장애':22s} {'등급':5s} {'트리거':>4s}  {'번역':4s} {'제품':4s} {'점수':>5s}  판정")
print("─" * 78)
bad = 0
for label, fault in FAULTS.items():
    v, saved = run(fault)
    worse = risk.tier_rank(v.tier) > risk.tier_rank(base_v.tier)
    lost = base_v.triggers - v.triggers
    tr = "유지" if saved.get("title_ko") else "유실"
    pr = "유지" if saved.get("affected") else "유실"
    sc = saved.get("cvss", 0)
    okk = not worse and not lost and tr == "유지" and pr == "유지" and sc == 10.0
    if not okk:
        bad += 1
    print(f"{label:22s} {v.tier:5s} {len(v.triggers):>4d}  {tr:4s} {pr:4s} {sc:>5.1f}  "
          + ("OK" if okk else f"저하: {sorted(lost) or ''}"))
print("─" * 78)
print(f"{'모든 장애 조합에서 상태 저하 없음' if not bad else f'{bad}개 조합에서 저하'}")
sys.exit(1 if bad else 0)
