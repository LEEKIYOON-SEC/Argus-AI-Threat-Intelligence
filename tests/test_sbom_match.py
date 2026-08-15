#!/usr/bin/env python3
"""CLI(tools/sbom_match.py)와 대시보드(docs/js/cve-dashboard.js)의 판정이 같은지 검증한다.

같은 SBOM을 놓고 브라우저와 터미널이 다른 답을 내면 둘 다 못 믿게 된다. 실행 환경이
달라 코드는 공유할 수 없으므로, 같은 케이스 표를 양쪽에 먹여 결과가 일치하는지 본다.

    python3 tests/test_sbom_match.py

node가 없으면 파이썬 쪽 기대값 검사만 수행하고 교차 검증은 건너뛴다(사유를 출력).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))
import sbom_match as S  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")
JS_PATH = os.path.join(ROOT, "docs", "js", "cve-dashboard.js")

# ===== 케이스 표 =====
# 버전 비교: (a, b, 기대 부호)  — 문자열 정렬로는 틀리는 것들 위주
VERSION_CASES = [
    ("1.9.0", "1.10.0", -1),          # 문자열 정렬이면 뒤집힌다
    ("1.10.0", "1.9.0", 1),
    ("1.2.3", "1.2.3", 0),
    ("1:0.48-1", "0.49", 1),          # epoch가 upstream보다 우선
    ("0.49", "1:0.48-1", -1),
    ("1.0~rc1", "1.0", -1),           # '~'는 무엇보다 작다
    ("1.0", "1.0~rc1", 1),
    ("1.2.3-r0", "1.2.3-r1", -1),     # Alpine 리비전
    ("1.2.3-r1", "1.2.3-r0", 1),
    ("1.02", "1.2", 0),               # 앞의 0 무시
    ("1.2", "1.2.0", -1),             # 세그먼트 길이 차이
    ("7.88.1-10", "7.88.1-10+deb12u5", -1),
    ("6b18-1.8.13-0+squeeze1", "6b18-1.8.13-0+squeeze2", -1),
    ("2.4.57", "2.4.57", 0),
    ("", "1.0", -1),
    ("1.0", "", 1),
]

# 패키지명 정규화: (입력, 기대)
NORM_CASES = [
    ("libcurl4", "curl"),
    ("libssl3", "ssl"),
    ("python3.11", "python"),
    ("python3-requests", "requests"),
    ("openssl-dev", "openssl"),
    ("curl", "curl"),
    ("node-tar", "tar"),
    ("golang-github-x", "github-x"),
    ("", ""),
    ("LIBXML2", "xml"),
]

# 생태계 판정: (SBOM 행, 기대)
ECO_CASES = [
    ({"purl": "pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12"}, "Debian:12"),
    ({"purl": "pkg:apk/alpine/curl@8.5.0-r0?distro=alpine-3.19"}, "Alpine:v3.19"),
    ({"purl": "pkg:deb/ubuntu/curl@7.81.0?distro=ubuntu-22.04"}, "Ubuntu:22.04"),
    ({"purl": "pkg:npm/lodash@4.17.20"}, "npm"),
    ({"purl": "pkg:pypi/requests@2.28.0"}, "PyPI"),
    ({"purl": "pkg:maven/org.x/y@1.0"}, "Maven"),
    ({"purl": "pkg:golang/github.com/x/y@v1.0.0"}, "Go"),
    ({"purl": "", "type": "npm"}, "npm"),
    ({"purl": "", "type": ""}, ""),
    ({"purl": "pkg:gem/rails@7.0"}, ""),
]

# 버전 판정: (설치버전, 생태계맵, 내 생태계, 기대 verdict, 기대 target)
VERDICT_CASES = [
    ("7.88.1-10", {"Debian:12": ["7.88.1-10+deb12u5"]}, "Debian:12", "vulnerable", "7.88.1-10+deb12u5"),
    ("7.88.1-10+deb12u5", {"Debian:12": ["7.88.1-10+deb12u5"]}, "Debian:12", "fixed", ""),
    ("8.0.0", {"Debian:12": ["7.88.1-10+deb12u5"]}, "Debian:12", "fixed", ""),
    # 내 릴리스가 정확히 없으면 접두 일치로 떨어진다
    ("1.0", {"Debian:11": ["2.0"]}, "Debian:12", "vulnerable", "2.0"),
    # 여러 목표 중 가장 낮은 것을 제시
    ("1.0", {"npm": ["3.0", "2.0", "4.0"]}, "npm", "vulnerable", "2.0"),
    # 수정 버전이 없는 항목이 섞여 있어도 있는 쪽을 골라야 한다 (빈 배열 함정)
    ("1.0", {"Debian:12": [], "Debian:11": ["2.0"]}, "Debian:12", "vulnerable", "2.0"),
    ("1.0", {"Ubuntu:Pro:14.04:LTS": [], "npm": ["2.0"]}, "npm", "vulnerable", "2.0"),
    # 판정 불가
    ("1.0", {}, "npm", "unknown", ""),
    ("", {"npm": ["2.0"]}, "npm", "unknown", ""),
    ("1.0", {"npm": []}, "npm", "unknown", ""),
]

JS_FUNCS = ["normPkg", "splitDeb", "cmpChunk", "cmpVersion", "sbomEcosystem", "versionVerdict"]


def extract_js(names):
    """cve-dashboard.js에서 순수 함수만 잘라 온다.

    파일 전체를 평가하면 document·fetch 같은 브라우저 전역이 필요해진다. 대조할
    함수들은 서로만 의존하는 순수 함수라 중괄호를 세어 그 정의만 떼어내면 된다."""
    src = open(JS_PATH, encoding="utf-8").read()
    out = []
    for name in names:
        m = re.search(r"^function %s\s*\(" % re.escape(name), src, re.M)
        if not m:
            raise SystemExit(f"JS에서 {name}을 찾지 못했습니다 — 함수명이 바뀌었는지 확인하세요.")
        i = src.index("{", m.end() - 1)
        depth, j = 0, i
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append(src[m.start():j + 1])
    return "\n".join(out)


def run_js(payload):
    """같은 케이스 표를 JS로 돌린 결과를 받아 온다."""
    harness = extract_js(JS_FUNCS) + r"""
const IN = JSON.parse(process.argv[2]);
const sign = n => n < 0 ? -1 : n > 0 ? 1 : 0;
console.log(JSON.stringify({
  version: IN.version.map(([a, b]) => sign(cmpVersion(a, b))),
  norm: IN.norm.map(([s]) => normPkg(s)),
  eco: IN.eco.map(([row]) => sbomEcosystem(row)),
  verdict: IN.verdict.map(([v, m, w]) => {
    const r = versionVerdict(v, m, w);
    return [r.verdict, r.target];
  }),
}));
"""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "h.js")
        open(p, "w", encoding="utf-8").write(harness)
        r = subprocess.run([shutil.which("node"), p, json.dumps(payload)],
                           capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise SystemExit(f"node 실행 실패:\n{r.stderr}")
    return json.loads(r.stdout)


def main():
    fails = []

    def check(label, got, want):
        if got != want:
            fails.append(f"  {label}: 결과 {got!r} · 기대 {want!r}")

    # ---- 파이썬 기대값 ----
    py_version = [S.cmp_version(a, b) for a, b, _ in VERSION_CASES]
    for (a, b, want), got in zip(VERSION_CASES, py_version):
        check(f"cmp_version({a!r}, {b!r})", got, want)

    py_norm = [S.norm_pkg(s) for s, _ in NORM_CASES]
    for (s, want), got in zip(NORM_CASES, py_norm):
        check(f"norm_pkg({s!r})", got, want)

    py_eco = [S.sbom_ecosystem(row) for row, _ in ECO_CASES]
    for (row, want), got in zip(ECO_CASES, py_eco):
        check(f"sbom_ecosystem({row.get('purl') or row.get('type')!r})", got, want)

    py_verdict = []
    for inst, emap, weco, want_v, want_t in VERDICT_CASES:
        r = S.version_verdict(inst, emap, weco)
        py_verdict.append([r["verdict"], r["target"]])
        check(f"version_verdict({inst!r}, {emap!r})", [r["verdict"], r["target"]], [want_v, want_t])

    print(f"파이썬 기대값 검사: {len(VERSION_CASES) + len(NORM_CASES) + len(ECO_CASES) + len(VERDICT_CASES)}건")

    # ---- JS 교차 검증 ----
    if not shutil.which("node"):
        print("교차 검증 건너뜀 — node가 없습니다 (파이썬 검사만 수행).")
    else:
        js = run_js({
            "version": [[a, b] for a, b, _ in VERSION_CASES],
            "norm": [[s] for s, _ in NORM_CASES],
            "eco": [[row] for row, _ in ECO_CASES],
            "verdict": [[i, m, w] for i, m, w, _, _ in VERDICT_CASES],
        })
        for label, py, j in (("cmp_version", py_version, js["version"]),
                             ("norm_pkg", py_norm, js["norm"]),
                             ("sbom_ecosystem", py_eco, js["eco"]),
                             ("version_verdict", py_verdict, js["verdict"])):
            for k, (p, q) in enumerate(zip(py, j)):
                if p != q:
                    fails.append(f"  {label}[{k}] 불일치: 파이썬 {p!r} · JS {q!r}")
        print(f"JS 교차 검증: {sum(len(v) for v in js.values())}건")

    if fails:
        print(f"\n실패 {len(fails)}건:")
        print("\n".join(fails))
        return 1
    print("\n전부 통과 — CLI와 대시보드의 판정이 일치합니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
