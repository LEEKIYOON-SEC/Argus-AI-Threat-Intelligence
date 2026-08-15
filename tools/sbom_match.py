#!/usr/bin/env python3
"""syft SBOM과 Argus 추적 CVE를 내 PC에서 대조한다.

자산 목록 전체를 CVE와 맞춰보는 일은 여기서 한다. 브라우저에서 하려면 SBOM 파일을
올려야 하는데 파일 선택이 막힌 업무 환경에서는 쓸 수 없고, 자산 목록을 브라우저에
넣는 것 자체가 부담이다. 이 스크립트는 터미널에서 돌고 표준 라이브러리만 쓴다
(pip install 불필요). 대시보드는 CVE별 패키지 이름과 패치 버전을 보여주는 데까지만 한다.

  # syft로 SBOM을 뽑고
  syft dir:. -o syft-json | jq -r '["name","source","version","type","purl"],
      (.artifacts[] | [.name, (.metadata.source // ""), .version, .type, .purl]) | @csv' > sbom.csv

  # 대조
  python3 tools/sbom_match.py sbom.csv
  python3 tools/sbom_match.py sbom.csv --csv > result.csv
  python3 tools/sbom_match.py sbom.csv --offline ./data   # 망분리: 미리 받아둔 파일 사용

자산 목록은 어디로도 전송되지 않는다. 공개된 인덱스 파일을 GET할 뿐이고 CSV는 로컬에서만
읽는다. --offline이면 네트워크를 아예 쓰지 않는다.

버전 비교는 dpkg 규칙을 따른다 — 문자열 정렬은 1.10 < 1.9로 뒤집히고, epoch(1:)와
'~'(프리릴리스)를 무시하면 판정이 반대로 나온다.
"""
from __future__ import annotations

import argparse
import csv
import functools
import gzip
import json
import os
import re
import sys
import urllib.request
from typing import Dict, List, Optional, Tuple

DEFAULT_BASE_URL = "https://leekiyoon-sec.github.io/Argus-AI-Threat-Intelligence/data"

_DIGITS = "0123456789"
_ALPHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ===== 패키지명 정규화 =====
# 배포판이 이름에 붙이는 장식을 걷어낸다. OSV는 소스 패키지명 기준이라
# libcurl4 → curl 처럼 접두/접미를 벗겨야 맞는다.
_PRE = re.compile(r"^(lib|python3?-|py3?-|perl-|ruby-|golang-|node-|php-)")
_SUF = re.compile(r"-(dev|devel|common|utils|bin|doc|data|runtime|tools)$")
_TAIL = re.compile(r"[0-9._-]+$")


def norm_pkg(name: str) -> str:
    s = str(name or "").lower().strip()
    if not s:
        return ""
    s = _PRE.sub("", s, count=1)
    s = _SUF.sub("", s, count=1)
    s = _TAIL.sub("", s, count=1)      # 끝의 버전 꼬리 (libssl3, python3.11)
    return s


# ===== 버전 비교 =====
# 문자열 정렬은 1.10 < 1.9로 뒤집히므로 세그먼트 단위로 본다.
# dpkg 규칙: epoch(N:) 우선, 그다음 upstream, 마지막 revision.
# '~'는 어떤 것보다도 작다 — 1.0~rc1 < 1.0 (프리릴리스 표기).
_DEB = re.compile(r"^(?:(\d+):)?(.*?)(?:-([^-]*))?$")


def split_deb(v: str) -> Tuple[int, str, str]:
    m = _DEB.match(str(v or "").strip())
    if not m:
        return 0, "", ""
    return int(m.group(1) or 0), m.group(2) or "", m.group(3) or ""


def _rank(s: str, i: int) -> int:
    """한 글자의 dpkg 순위. 범위를 넘으면 0(JS의 undefined와 같게)."""
    if i >= len(s):
        return 0
    c = s[i]
    if c == "~":
        return -1
    if c in _DIGITS:
        return 0
    if c in _ALPHA:
        return ord(c)
    return ord(c) + 256


def cmp_chunk(a: str, b: str) -> int:
    """한 조각을 dpkg 순서로 비교. 숫자는 수치로, 문자는 사전순, '~'는 최하위."""
    i = j = 0
    while i < len(a) or j < len(b):
        # 비숫자 구간 비교
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            d = _rank(a, i) - _rank(b, j)
            if d:
                return -1 if d < 0 else 1
            i += 1
            j += 1
        # 숫자 구간 비교 (앞의 0 무시)
        na = nb = ""
        while i < len(a) and a[i] in _DIGITS:
            na += a[i]
            i += 1
        while j < len(b) and b[j] in _DIGITS:
            nb += b[j]
            j += 1
        va, vb = int(na or "0"), int(nb or "0")
        if va != vb:
            return -1 if va < vb else 1
        if i >= len(a) and j >= len(b):
            break
    return 0


def cmp_version(a: str, b: str) -> int:
    ea, ua, ra = split_deb(a)
    eb, ub, rb = split_deb(b)
    if ea != eb:
        return -1 if ea < eb else 1
    u = cmp_chunk(ua, ub)
    if u:
        return u
    return cmp_chunk(ra, rb)


# ===== 생태계 =====
# syft purl 예: pkg:deb/debian/curl@7.88.1-10?arch=amd64&distro=debian-12 → Debian:12
_DISTRO = re.compile(r"distro=([a-z]+)-?([0-9.]*)", re.I)
_PTYPE = re.compile(r"^pkg:([a-z]+)/", re.I)
_TYPE_MAP = {"npm": "npm", "pypi": "PyPI", "python": "PyPI", "maven": "Maven",
             "golang": "Go", "go": "Go", "apk": "Alpine", "deb": "Debian"}


def _series(v: str) -> str:
    """버전의 갈래(major.minor). epoch(1:)와 리비전은 떼고 본다 — 1:9.0.116 → 9.0."""
    up = split_deb(v)[1]
    m = re.match(r"^(\d+\.\d+)", up)
    return m.group(1) if m else ""


def sbom_ecosystem(row: Dict) -> str:
    purl = str(row.get("purl") or "")
    m = _DISTRO.search(purl)
    if m and m.group(1):
        name, ver = m.group(1).lower(), m.group(2) or ""
        if name == "debian":
            return f"Debian:{ver}" if ver else "Debian"
        if name == "ubuntu":
            return f"Ubuntu:{ver}" if ver else "Ubuntu"
        if name == "alpine":
            return f"Alpine:v{ver}" if ver else "Alpine"
    t = _PTYPE.match(purl)
    typ = (t.group(1) if t else str(row.get("type") or "")).lower()
    return _TYPE_MAP.get(typ, "")


def version_verdict(installed: str, eco_map: Optional[Dict[str, List[str]]],
                    want_eco: str) -> Dict[str, str]:
    """설치 버전이 수정판인지 판정. verdict: vulnerable | fixed | unknown."""
    if not eco_map:
        return {"verdict": "unknown", "target": "", "eco": ""}

    # 수정 버전이 실제로 있는 생태계만 후보로 본다 — 빈 항목을 고르면 다른 릴리스에
    # 수정 버전이 있는데도 '미확인'으로 떨어진다.
    def has(k: str) -> bool:
        v = eco_map.get(k)
        return isinstance(v, list) and any(v)

    eco = want_eco if (want_eco and has(want_eco)) else ""
    if not eco and want_eco:
        base = want_eco.split(":")[0]
        eco = next((k for k in eco_map if has(k) and (k == base or k.split(":")[0] == base)), "")
    if not eco:
        eco = next((k for k in eco_map if has(k)), "") or next(iter(eco_map), "")

    fixes = [f for f in (eco_map.get(eco) or []) if f]
    if not fixes or not installed:
        return {"verdict": "unknown", "target": "", "eco": eco}
    try:
        # 설치본과 같은 갈래(major.minor)의 수정본이 있으면 그것만 본다.
        #
        # 여러 갈래를 동시에 관리하는 제품이 흔하다 — Tomcat 9 / 10.1 / 11,
        # Quarkus 3.8 / 3.15 / 3.18. OSV는 갈래별 수정본을 모두 주는데, 전체에서
        # 최저값을 고르면 다른 갈래의 번호를 답으로 내놓게 된다. 그냥 틀린 답이
        # 아니라 위험하다: Tomcat 10.1.40(취약)이 최저값 9.0.116보다 높다는 이유로
        # '수정판'으로 판정돼, 고쳐야 할 것을 안전하다고 보고한다.
        # 같은 갈래가 없으면(예: 8.5.x 사용 중인데 수정본은 9/10/11뿐) 전체를 본다.
        branch = _series(installed)
        same = [f for f in fixes if branch and _series(f) == branch]
        pool = same or fixes
        # 하나라도 설치버전 이하면 이미 그 수정본을 넘어선 것
        if any(cmp_version(installed, f) >= 0 for f in pool):
            return {"verdict": "fixed", "target": "", "eco": eco}
        # 아직이면 가장 낮은 목표를 올릴 버전으로 제시
        target = sorted(pool, key=functools.cmp_to_key(cmp_version))[0]
        return {"verdict": "vulnerable", "target": target, "eco": eco}
    except Exception:
        return {"verdict": "unknown", "target": fixes[0], "eco": eco}


# ===== SBOM 읽기 =====
def parse_sbom_csv(path: str) -> List[Dict]:
    """syft/jq가 뽑은 CSV를 읽는다. name 열은 필수, 나머지는 있으면 쓴다."""
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.reader(f)
        try:
            head = [h.strip().lower() for h in next(reader)]
        except StopIteration:
            return []
        if "name" not in head:
            raise SystemExit(f"오류: CSV에 'name' 열이 없습니다 (헤더: {', '.join(head) or '없음'})")

        def col(n: str) -> int:
            return head.index(n) if n in head else -1

        idx = {k: col(k) for k in ("name", "source", "version", "type", "purl")}
        rows = []
        for f_ in reader:
            def get(k: str) -> str:
                i = idx[k]
                return f_[i].strip() if 0 <= i < len(f_) else ""
            if not get("name"):
                continue
            rows.append({k: get(k) for k in idx})
        return rows


def index_sbom(rows: List[Dict]) -> Dict[str, Dict]:
    """정규화 키 → 원본 행. 소스명이 있으면 그쪽이 정답이고, 없으면 name을 쓴다."""
    keys: Dict[str, Dict] = {}
    for r in rows:
        for cand in (r.get("source"), r.get("name")):
            if not cand:
                continue
            for k in (cand.lower(), norm_pkg(cand)):
                if k and k not in keys:
                    keys[k] = r
    return keys


def sbom_match(cve: Dict, keys: Dict[str, Dict], pkg_index: Dict) -> Optional[Dict]:
    """CVE 하나가 내 SBOM의 어느 줄과 맞는지. 없으면 None."""
    pkg_map = pkg_index.get(cve.get("id")) or {}
    for p in pkg_map:                                   # 1순위: OSV 사전 (정확)
        hit = keys.get(str(p).lower()) or keys.get(norm_pkg(p))
        if hit:
            v = version_verdict(hit.get("version", ""), pkg_map[p], sbom_ecosystem(hit))
            return {"row": hit, "via": "osv", "pkg": p, **v}
    for a in (cve.get("affected") or []):               # 2순위: 제품명 정규화 (보조)
        prod = a.get("product") or ""
        if not prod:
            continue
        hit = keys.get(prod.lower()) or keys.get(norm_pkg(prod))
        # 이름 정규화로 붙은 건 OSV 사전에 없어 수정 버전을 모른다 → 판정 보류
        if hit:
            return {"row": hit, "via": "name", "pkg": prod,
                    "verdict": "unknown", "target": "", "eco": ""}
    return None


# ===== 데이터 적재 =====
def load_json(name: str, base_url: str, offline: Optional[str]) -> Optional[Dict]:
    if offline:
        path = os.path.join(offline, name)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    url = f"{base_url.rstrip('/')}/{name}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "argus-sbom-match", "Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        raw = resp.read()
        if resp.headers.get("Content-Encoding") == "gzip":
            raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8"))


# ===== 출력 =====
_VERDICT_KO = {"vulnerable": "취약 추정", "fixed": "수정판 추정", "unknown": "버전 미확인"}
_ORDER = {"vulnerable": 0, "unknown": 1, "fixed": 2}
_SEV_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "None": 4}


def build_results(cves: List[Dict], keys: Dict[str, Dict], pkg_index: Dict) -> List[Dict]:
    out = []
    for cve in cves:
        m = sbom_match(cve, keys, pkg_index)
        if not m:
            continue
        row = m["row"]
        out.append({
            "cve": cve.get("id", ""),
            "kernel": bool(cve.get("is_kernel")),
            "severity": cve.get("severity", "None"),
            "cvss": cve.get("cvss") or "",
            "kev": "Y" if cve.get("is_kev") else "",
            "package": row.get("name", ""),
            "installed": row.get("version", ""),
            "target": m.get("target", ""),
            "verdict": m.get("verdict", "unknown"),
            "ecosystem": m.get("eco", ""),
            "matched_by": m.get("via", ""),
            "matched_key": m.get("pkg", ""),
            "title": cve.get("title", ""),
            "report_url": cve.get("report_url", ""),
        })
    out.sort(key=lambda r: (_ORDER.get(r["verdict"], 3),
                            0 if r["kev"] else 1,
                            _SEV_ORDER.get(r["severity"], 5),
                            -(float(r["cvss"]) if r["cvss"] else 0)))
    return out


_COLLAPSE_MIN = 20


def package_summary(pkg: str, rows: List[Dict]) -> str:
    """CVE가 쏟아지는 패키지 하나를 한 줄로 접는다.

    커널이 대표적이다 — CVE마다 고치는 게 아니라 패키지를 한 번 올리는 단위인데,
    수천 줄을 늘어놓으면 정작 손댈 다른 패키지가 안 보인다(실측: 4,301건 중 4,297건이
    커널이라 나머지 4건이 묻혔다). 커널 플래그(is_kernel)가 아니라 건수로 접는 이유는
    그 플래그가 linux 패키지 행을 전부 덮지 못하고, 같은 문제가 다른 패키지에서도
    생길 수 있어서다.

    목표 버전은 설치된 것과 같은 시리즈(major.minor) 안에서 가장 높은 것을 고른다.
    전체 최댓값을 쓰면 6.1 계열 사용자에게 7.1로 올리라는 엉뚱한 답이 나간다."""
    vuln = [r for r in rows if r["verdict"] == "vulnerable"]
    installed = rows[0]["installed"]
    kev = sum(1 for r in rows if r["kev"])
    branch = _series(installed or "")
    target = ""
    if branch:
        same = [r["target"] for r in vuln if _series(r["target"] or "") == branch]
        if same:
            target = sorted(same, key=functools.cmp_to_key(cmp_version))[-1]
    goal = f" → {target}" if target else ""
    kevs = f" · KEV {kev}건" if kev else ""
    return (f"[묶음] {pkg} {installed}{goal} — 관련 CVE {len(rows):,}건"
            f"(취약 추정 {len(vuln):,}{kevs})")


def print_table(results: List[Dict]) -> None:
    cols = [("cve", "CVE"), ("severity", "심각도"), ("kev", "KEV"),
            ("package", "패키지"), ("installed", "설치"), ("target", "→ 목표"),
            ("verdict", "판정")]
    rows = [{**r, "verdict": _VERDICT_KO.get(r["verdict"], r["verdict"])} for r in results]
    width = {k: max(len(h), *(len(str(r[k])) for r in rows)) for k, h in cols}
    print("  ".join(h.ljust(width[k]) for k, h in cols))
    print("  ".join("-" * width[k] for k, _ in cols))
    for r in rows:
        print("  ".join(str(r[k]).ljust(width[k]) for k, _ in cols))


def main() -> int:
    ap = argparse.ArgumentParser(
        description="syft SBOM과 Argus 추적 CVE를 로컬에서 대조합니다 (자산 목록은 전송되지 않습니다).")
    ap.add_argument("sbom", help="syft가 뽑은 CSV 경로 (name 열 필수)")
    ap.add_argument("--offline", metavar="DIR",
                    help="네트워크 대신 이 디렉터리의 cve-packages.json·cves.json을 사용")
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help="인덱스 파일 위치 (기본: GitHub Pages)")
    ap.add_argument("--csv", action="store_true", help="CSV로 출력")
    ap.add_argument("--json", action="store_true", help="JSON으로 출력")
    ap.add_argument("--check-malicious", action="store_true",
                    help="알려진 악성 패키지(OSV MAL) 이름 대조도 수행 (목록 5MB 추가 다운로드)")
    ap.add_argument("--all", action="store_true",
                    help="수정판으로 추정되는 항목까지 모두 출력 (기본은 취약·미확인만)")
    ap.add_argument("--expand", action="store_true",
                    help=f"CVE가 {_COLLAPSE_MIN}건 넘는 패키지(커널 등)도 한 줄 요약 대신 전부 출력")
    args = ap.parse_args()

    quiet = args.csv or args.json

    def info(msg: str) -> None:
        if not quiet:
            print(msg, file=sys.stderr)

    try:
        rows = parse_sbom_csv(args.sbom)
    except OSError as e:
        print(f"오류: SBOM 파일을 읽지 못했습니다 — {e}", file=sys.stderr)
        return 1
    if not rows:
        print("오류: SBOM에서 읽은 패키지가 0건입니다.", file=sys.stderr)
        return 1
    info(f"SBOM {len(rows):,}개 패키지 읽음")

    src = args.offline or args.base_url
    info(f"인덱스 적재 중: {src}")
    try:
        pkg_doc = load_json("cve-packages.json", args.base_url, args.offline)
        cve_doc = load_json("cves.json", args.base_url, args.offline)
    except Exception as e:
        print(f"오류: 인덱스를 불러오지 못했습니다 ({e})", file=sys.stderr)
        print("  네트워크가 막혀 있다면 두 파일을 미리 받아 --offline DIR 로 지정하세요.", file=sys.stderr)
        return 1
    if pkg_doc is None or cve_doc is None:
        print(f"오류: {args.offline}에 cve-packages.json·cves.json이 필요합니다.", file=sys.stderr)
        return 1

    pkg_index = pkg_doc.get("packages", pkg_doc) if isinstance(pkg_doc, dict) else {}
    cves = cve_doc if isinstance(cve_doc, list) else (cve_doc.get("cves") or [])
    info(f"추적 CVE {len(cves):,}건 · 패키지 인덱스 {len(pkg_index):,}건")

    keys = index_sbom(rows)
    results = build_results(cves, keys, pkg_index)
    shown = results if args.all else [r for r in results if r["verdict"] != "fixed"]

    if args.json:
        json.dump(shown, sys.stdout, ensure_ascii=False, indent=2)
        print()
    elif args.csv:
        w = csv.DictWriter(sys.stdout, fieldnames=list(shown[0].keys()) if shown else
                           ["cve", "severity", "cvss", "kev", "package", "installed", "target",
                            "verdict", "ecosystem", "matched_by", "matched_key", "title",
                            "report_url"])
        w.writeheader()
        w.writerows(shown)
    elif not shown:
        print("일치하는 CVE가 없습니다.")
    else:
        # CSV·JSON은 전량을 그대로 낸다(기계가 읽는 출력) — 접는 것은 화면 문제다.
        by_pkg: Dict[str, List[Dict]] = {}
        for r in shown:
            by_pkg.setdefault(r["package"], []).append(r)
        big = {} if args.expand else {p: rs for p, rs in by_pkg.items()
                                      if len(rs) >= _COLLAPSE_MIN}
        body = [r for r in shown if r["package"] not in big]
        if body:
            print_table(body)
        if big:
            print(("\n" if body else "") + "\n".join(
                package_summary(p, rs) for p, rs in
                sorted(big.items(), key=lambda kv: -len(kv[1]))))
            print(f"  ({len(big)}개 패키지를 접었습니다 — 개별 목록은 --expand)")

    if not quiet:
        n_vuln = sum(1 for r in results if r["verdict"] == "vulnerable")
        n_fix = sum(1 for r in results if r["verdict"] == "fixed")
        n_unk = sum(1 for r in results if r["verdict"] == "unknown")
        print(f"\n합계 {len(results):,}건 — 취약 추정 {n_vuln:,} · 버전 미확인 {n_unk:,} · "
              f"수정판 추정 {n_fix:,}" + ("" if args.all else " (수정판은 --all로 표시)"))

    if args.check_malicious:
        _report_malicious(rows, args, quiet)

    return 0


def _report_malicious(rows: List[Dict], args, quiet: bool) -> None:
    """알려진 악성 패키지 이름 대조.

    취약점과 성격이 다르다 — 고치는 게 아니라 '설치되어 있으면 안 되는 것'이다.
    이름만 대조하므로 확정이 아니라 '확인해 보라'는 경고다."""
    try:
        doc = load_json("malicious-packages.json", args.base_url, args.offline)
    except Exception as e:
        print(f"악성 패키지 목록을 불러오지 못했습니다 ({e})", file=sys.stderr)
        return
    if not doc:
        return
    names = set(doc.get("names") or [])
    if not names:
        return
    hits = []
    for r in rows:
        # npm·PyPI 행만 검사한다 — deb 패키지가 npm 악성 이름과 우연히 겹치는 오탐 배제
        if sbom_ecosystem(r) not in ("npm", "PyPI"):
            continue
        if str(r.get("name", "")).lower() in names:
            hits.append(r)
    out = sys.stderr if quiet else sys.stdout
    if not hits:
        print(f"\n악성 패키지 대조: 일치 없음 (목록 {len(names):,}개)", file=out)
        return
    print(f"\n⚠️  알려진 악성 패키지와 이름이 일치하는 항목 {len(hits)}건", file=out)
    for r in hits:
        v = f"@{r['version']}" if r.get("version") else ""
        print(f"    {r['name']}{v}", file=out)
    print("    공급망 공격으로 배포된 패키지 목록(OSV)과 이름만 대조한 결과입니다.", file=out)
    print("    이름이 재사용됐을 수 있으니 https://osv.dev 에서 해당 버전을 확인하세요.", file=out)


if __name__ == "__main__":
    sys.exit(main())
