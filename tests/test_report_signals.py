#!/usr/bin/env python3
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["ARGUS_CACHE_DIR"] = tempfile.mkdtemp()
for _k in ("GH_TOKEN", "SUPABASE_URL", "SUPABASE_KEY", "SLACK_WEBHOOK_URL", "GEMINI_API_KEY"):
    os.environ.setdefault(_k, "test")
os.environ.pop("GITHUB_REPOSITORY", None)

import pipeline  # noqa: E402
import report  # noqa: E402
import rule_manager  # noqa: E402
from analyzer import Analyzer  # noqa: E402


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def _prompt(data):
    return Analyzer.__dict__["_build_analysis_prompt"](object.__new__(Analyzer), data)


class DB:
    def __init__(self, rows=None):
        self.rows = rows or {}

    def get_cve(self, cid):
        return self.rows.get(cid)

    def upsert_cve(self, p):
        self.rows.setdefault(p["id"], {}).update(p)
        return True


class Slack:
    def send_alert(self, *a, **k):
        return True


def rule_index_unavailable(failures):
    print("── 룰 인덱스를 못 받은 회차 ──")
    rule_manager._LOCAL = os.path.join(os.environ["ARGUS_CACHE_DIR"], "missing.json")
    rule_manager._INDEX = None
    rule_manager._INDEX_OK = False
    check(rule_manager.index_ok() is False,
          "index_ok() 가 False — '룰 없음'이 아니라 '못 받음'으로 안다", failures)

    known = {"CVE-2021-44228": {"id": "CVE-2021-44228", "has_official_rules": True,
                                "rules_snapshot": {"sigma": {"code": "title: x"}}}}
    db = DB(known)
    state = {"id": "CVE-2021-44228", "is_kev": True, "cvss": 10.0, "title": "L",
             "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}
    pipeline.process(dict(state), db, Slack(),
                     make_report=lambda s, r: ("https://github.com/x/issues/1", None))
    row = db.rows["CVE-2021-44228"]
    check(row.get("has_official_rules") is True,
          f"이전에 확인한 '룰 있음'을 False 로 덮지 않는다 ({row.get('has_official_rules')})",
          failures)
    check((row.get("rules_snapshot") or {}).get("sigma") is not None,
          "rules_snapshot 도 빈 껍데기로 지워지지 않는다", failures)

    print("\n── 인덱스가 정상인 회차 ──")
    path = os.path.join(os.environ["ARGUS_CACHE_DIR"], "detection-rules.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"rules": {"CVE-2021-44228": [
            {"engine": "nuclei", "source": "nuclei-templates", "code": "id: log4j",
             "license": "MIT", "url": "https://example.invalid/x.yaml"}]}}, f)
    rule_manager._LOCAL = path
    rule_manager._INDEX = None
    rule_manager._INDEX_OK = False
    check(rule_manager.index_ok() is True, "index_ok() 가 True", failures)
    rules = rule_manager.RuleManager().search_public_only("CVE-2021-44228")
    check(rules.get("nuclei") is not None, "nuclei 룰을 돌려준다", failures)

    db2 = DB()
    pipeline.process(dict(state), db2, Slack(),
                     make_report=lambda s, r: ("https://github.com/x/issues/2",
                                               {"has_official": True, "rules": rules}))
    check(db2.rows["CVE-2021-44228"].get("has_official_rules") is True,
          "정상 회차는 평소대로 기록한다", failures)


def _has_official(rules):
    return bool(any(r.get("verified") for r in rules.get("network") or [])
                or any((rules.get(k) or {}).get("verified")
                       for k in ("sigma", "yara", "nuclei", "splunk")))


def recheck_engines(failures):
    print("\n── 재확인이 모든 엔진을 인정하는가 ──")
    for eng in ("sigma", "yara", "nuclei", "splunk"):
        rules = {"sigma": None, "yara": None, "nuclei": None, "splunk": None,
                 "network": [], eng: {"verified": True, "code": "x", "source": "s"}}
        check(_has_official(rules) is True,
              f"{eng} 만 찾아도 '공식 룰 발견'으로 센다", failures)
    empty = {"sigma": None, "yara": None, "nuclei": None, "splunk": None, "network": []}
    check(_has_official(empty) is False, "아무것도 없으면 False", failures)
    net = dict(empty, network=[{"verified": True, "code": "alert", "source": "s"}])
    check(_has_official(net) is True, "네트워크 룰도 인정", failures)


def unknown_is_not_zero(failures):
    print("\n── 지표를 못 받았을 때 리포트 표기 ──")
    base = {"id": "CVE-2026-9", "cvss": 9.8, "title": "T", "cwe": [],
            "cvss_vector": "CVSS:3.1/AV:N", "references": [], "affected": []}
    body = report._build_issue_body(base, "테스트", {}, {})
    check("EPSS-unknown" in body, "EPSS 배지가 unknown", failures)
    check("KEV-unknown" in body, "KEV 배지가 unknown", failures)
    check("EPSS 미상" in body, "설명도 '미상'이라고 말한다", failures)
    check("EPSS 0.00%" not in body,
          "못 받은 값을 0.00% 로 적지 않는다 — 화면은 위험을 낮춰 부르지 않는다", failures)

    real = dict(base, epss=0.0, epss_percentile=0.0, is_kev=False)
    body2 = report._build_issue_body(real, "테스트", {}, {})
    check("EPSS-0.00%25-blue" in body2, "실제로 관측된 0 은 0 으로 적는다", failures)
    check("KEV-No-CCCCCC" in body2, "실제로 미등재면 No", failures)

    kev = dict(base, epss=0.9, is_kev=True)
    body3 = report._build_issue_body(kev, "테스트", {}, {})
    check("KEV-YES-FF0000" in body3, "등재면 YES", failures)
    check("EPSS-90.00%25-blue" in body3, "값이 있으면 값을 적는다", failures)


def poc_and_prompt(failures):
    print("\n── PoC 건수와 AI 프롬프트 ──")
    poc = {"id": "CVE-2026-9", "cvss": 9.8, "title": "T", "cwe": [],
           "cvss_vector": "CVSS:3.1/AV:N", "references": [], "affected": [],
           "description": "Remote code execution.", "has_poc": True,
           "poc_urls": ["https://github.com/a/b", "https://github.com/c/d"]}
    body = report._build_issue_body(poc, "테스트", {}, {})
    check("2건" in body, "리포트가 실제 PoC 개수를 적는다", failures)

    prompt = _prompt(poc)
    check("PoC: 공개됨 (2건)" in prompt, "AI 프롬프트도 실제 개수를 준다", failures)
    check("(0건)" not in prompt,
          "'공개됨 (0건)' 같은 모순된 문장을 AI 에게 주지 않는다", failures)

    msf = dict(poc, has_metasploit_module=True, metasploit_modules=["exploit/x"])
    check("Metasploit: 모듈 존재 - exploit/x" in _prompt(msf),
          "무기화 사실이 AI 프롬프트에 실린다", failures)

    print("\n── description 이 없는 낡은 행 ──")
    old = {"id": "CVE-2019-1", "cvss": 9.0, "cvss_vector": "CVSS:3.1/AV:N"}
    try:
        check("Description: N/A" in _prompt(old),
              "description 이 없어도 프롬프트가 만들어진다 "
              "(터지면 리포트 보강이 같은 행을 영원히 재시도한다)", failures)
    except Exception as e:
        check(False, f"description 이 없으면 터진다: {type(e).__name__}: {e}", failures)


def main() -> int:
    failures = []
    rule_index_unavailable(failures)
    recheck_engines(failures)
    unknown_is_not_zero(failures)
    poc_and_prompt(failures)
    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
