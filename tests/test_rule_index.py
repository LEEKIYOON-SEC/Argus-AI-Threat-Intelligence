#!/usr/bin/env python3
import json
import os
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
os.environ["ARGUS_CACHE_DIR"] = tempfile.mkdtemp()
os.environ.pop("GITHUB_REPOSITORY", None)

import build_rule_index as bri  # noqa: E402

ET_LINE = ('alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"ET EXPLOIT Log4j"; '
           'reference:cve,2021-44228; sid:2034647; rev:2;)')
SNORT_LINE = ('alert tcp any any -> any 8080 (msg:"SERVER Apache Log4j"; '
              'reference:cve,2021-44228; sid:58722; rev:1;)')


def check(cond, msg, failures):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        failures.append(msg)


def network_dedup(failures):
    print("── 같은 CVE 에 대한 네트워크 룰 여러 개 ──")
    index = {}
    for label, engine, line in (("Snort 2.9 Community", "snort2", SNORT_LINE),
                                ("Snort 2.9 ET Open", "snort2", ET_LINE)):
        bri._add(index, "CVE-2021-44228", {
            "engine": engine, "source": label, "license": "MIT", "note": "",
            "path": bri._network_key(label, line), "url": "", "code": line})
    got = index["CVE-2021-44228"]
    check(len(got) == 2,
          f"출처가 다른 룰 2개가 모두 남는다 ({len(got)}개) — "
          f"path 가 빈 문자열이면 하나만 남았다", failures)
    check(len({e["code"] for e in got}) == 2, "실제로 서로 다른 룰이다", failures)

    bri._add(index, "CVE-2021-44228", {
        "engine": "snort2", "source": "Snort 2.9 ET Open", "license": "MIT", "note": "",
        "path": bri._network_key("Snort 2.9 ET Open", ET_LINE), "url": "", "code": ET_LINE})
    check(len(index["CVE-2021-44228"]) == 2, "같은 룰을 다시 넣으면 중복되지 않는다", failures)

    print("\n── 엔진별 상한 ──")
    many = {}
    for i in range(10):
        line = f'alert tcp any any -> any any (msg:"x"; sid:{9000 + i};)'
        bri._add(many, "CVE-2021-44228", {
            "engine": "snort2", "source": "ET Open", "license": "MIT", "note": "",
            "path": bri._network_key("ET Open", line), "url": "", "code": line})
    check(len(many["CVE-2021-44228"]) == bri.MAX_PER_ENGINE,
          f"한 엔진당 {bri.MAX_PER_ENGINE}개까지만 싣는다 "
          f"({len(many['CVE-2021-44228'])}개) — 없으면 인덱스가 17MB 로 부푼다", failures)
    for eng in ("sigma", "nuclei"):
        for i in range(5):
            bri._add(many, "CVE-2021-44228",
                     {"engine": eng, "source": "s", "path": f"{eng}/{i}.yml", "url": ""})
    per = {}
    for e in many["CVE-2021-44228"]:
        per[e["engine"]] = per.get(e["engine"], 0) + 1
    check(all(v <= bri.MAX_PER_ENGINE for v in per.values()),
          f"상한은 엔진마다 따로 적용된다 ({per})", failures)

    key = bri._network_key("X", ET_LINE)
    check(key.endswith("sid2034647"), f"sid 를 키로 쓴다 ({key})", failures)
    nosid = bri._network_key("X", 'alert tcp any any -> any any (msg:"CVE-2021-44228";)')
    check(len(nosid) > 2 and "sid" not in nosid,
          f"sid 가 없으면 내용 해시로 구분한다 ({nosid})", failures)


def partial_failure(failures):
    print("\n── 일부 소스만 실패한 회차 ──")
    prev = {
        "CVE-2021-44228": [
            {"engine": "sigma", "source": "SigmaHQ", "path": "rules/web/log4j.yml",
             "url": "https://github.com/SigmaHQ/sigma/blob/master/rules/web/log4j.yml"},
            {"engine": "nuclei", "source": "nuclei-templates", "path": "http/cves/log4j.yaml",
             "url": "https://example.invalid/log4j.yaml"},
        ],
        "CVE-2023-1": [
            {"engine": "splunk", "source": "Splunk ESCU", "path": "detections/a.yml",
             "url": "https://example.invalid/a.yml"},
        ],
    }

    index = {}
    bri._add(index, "CVE-2021-44228", {"engine": "nuclei", "source": "nuclei-templates",
                                       "path": "http/cves/log4j.yaml",
                                       "url": "https://example.invalid/log4j.yaml"})
    missing = set(bri.ALL_ENGINES) - {"nuclei"}
    carried = bri.carry_missing(index, prev, missing)

    check(carried == 2, f"실패한 엔진의 직전 항목을 이월한다 ({carried}개)", failures)
    engines = {e["engine"] for e in index["CVE-2021-44228"]}
    check(engines == {"nuclei", "sigma"},
          f"nuclei 는 새로 받은 것, sigma 는 이월분 ({sorted(engines)})", failures)
    check("CVE-2023-1" in index, "이번 회차에 안 나온 CVE 도 이월로 살아난다", failures)
    check(len(index["CVE-2021-44228"]) == 2,
          "새로 받은 nuclei 가 이월분으로 중복되지 않는다", failures)

    print("\n── 이월이 새 결과를 덮지 않는다 ──")
    index2 = {}
    bri._add(index2, "CVE-2021-44228", {"engine": "nuclei", "source": "nuclei-templates",
                                        "path": "http/cves/log4j-v2.yaml",
                                        "url": "https://example.invalid/v2.yaml"})
    bri.carry_missing(index2, prev, set(bri.ALL_ENGINES) - {"nuclei"})
    nuclei = [e for e in index2["CVE-2021-44228"] if e["engine"] == "nuclei"]
    check(len(nuclei) == 1 and nuclei[0]["path"] == "http/cves/log4j-v2.yaml",
          f"갱신에 성공한 엔진은 새 값만 남는다 ({[e['path'] for e in nuclei]})", failures)

    print("\n── 이월 대상이 아닌 엔진은 손대지 않는다 ──")
    index3 = {}
    check(bri.carry_missing(index3, prev, set()) == 0, "missing 이 비면 아무것도 안 한다",
          failures)
    check(index3 == {}, "인덱스도 그대로", failures)


def previous_loader(failures):
    print("\n── 직전 인덱스 로더 ──")
    tmp = os.path.join(os.environ["ARGUS_CACHE_DIR"], "detection-rules.json")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"rules": {"CVE-2021-44228": [{"engine": "sigma", "path": "a.yml"}]}}, f)
    real_out = bri._OUT
    bri._OUT = tmp
    try:
        check(bri.load_previous().get("CVE-2021-44228") is not None,
              "체크아웃 사본에서 읽는다", failures)
        bri._OUT = os.path.join(os.environ["ARGUS_CACHE_DIR"], "nope.json")
        check(bri.load_previous() == {}, "없으면 빈 dict — 터지지 않는다", failures)
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("{ broken")
        bri._OUT = tmp
        check(bri.load_previous() == {}, "깨져 있어도 터지지 않는다", failures)
    finally:
        bri._OUT = real_out


def engine_coverage(failures):
    print("\n── 엔진 목록이 수집기와 일치하는가 ──")
    produced = {"nuclei", "sigma", "splunk", "yara", "snort2", "snort3",
                "suricata5", "suricata7"}
    check(set(bri.ALL_ENGINES) == produced,
          f"LICENSES 키가 실제 생성 엔진과 같다 "
          f"(빠짐 {sorted(produced - set(bri.ALL_ENGINES))} · "
          f"군더더기 {sorted(set(bri.ALL_ENGINES) - produced)})", failures)
    net_engines = {e for _, _, _, e in bri._NETWORK_SOURCES}
    check(net_engines <= set(bri.ALL_ENGINES),
          "네트워크 소스의 엔진이 전부 LICENSES 에 있다 (KeyError 방지)", failures)


def main() -> int:
    failures = []
    network_dedup(failures)
    partial_failure(failures)
    previous_loader(failures)
    engine_coverage(failures)
    print(f"\n{'통과' if not failures else '실패 ' + str(len(failures)) + '건'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
