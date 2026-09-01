#!/usr/bin/env python3
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


_PRE = re.compile(r"^(lib|python3?-|py3?-|perl-|ruby-|golang-|node-|php-)")
_SUF = re.compile(r"-(dev|devel|common|utils|bin|doc|data|runtime|tools)$")
_TAIL = re.compile(r"[0-9._-]+$")


def norm_pkg(name: str) -> str:
    s = str(name or "").lower().strip()
    if not s:
        return ""
    s = _PRE.sub("", s, count=1)
    s = _SUF.sub("", s, count=1)
    s = _TAIL.sub("", s, count=1)
    return s


_DEB = re.compile(r"^(?:(\d+):)?(.*?)(?:-([^-]*))?$")


def split_deb(v: str) -> Tuple[int, str, str]:
    m = _DEB.match(str(v or "").strip())
    if not m:
        return 0, "", ""
    return int(m.group(1) or 0), m.group(2) or "", m.group(3) or ""


def _rank(s: str, i: int) -> int:
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
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and a[i] not in _DIGITS) or (j < len(b) and b[j] not in _DIGITS):
            d = _rank(a, i) - _rank(b, j)
            if d:
                return -1 if d < 0 else 1
            i += 1
            j += 1
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


_DISTRO = re.compile(r"distro=([a-z]+)-?([0-9.]*)", re.I)
_PTYPE = re.compile(r"^pkg:([a-z]+)/", re.I)
_TYPE_MAP = {"npm": "npm", "pypi": "PyPI", "python": "PyPI", "maven": "Maven",
             "golang": "Go", "go": "Go", "apk": "Alpine", "deb": "Debian"}


def _series(v: str) -> str:
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


def eco_parts(eco: str) -> Tuple[str, str, str]:
    segs = [s for s in str(eco or "").split(":") if s]
    if not segs:
        return ("", "", "")
    rest = segs[1:]
    if rest and rest[-1].upper() == "LTS":
        rest = rest[:-1]
    release = rest[-1].lower() if rest else ""
    channel = "/".join(s.lower() for s in rest[:-1])
    return (segs[0].lower(), channel, release)


def pick_ecosystem(eco_map: Dict[str, List[str]], want_eco: str) -> Tuple[str, bool]:
    def has(k: str) -> bool:
        v = eco_map.get(k)
        return isinstance(v, list) and any(v)

    cands = [k for k in eco_map if has(k)]
    if not cands:
        return ("", False)
    if not want_eco:
        return (cands[0], False)

    wd, _, wr = eco_parts(want_eco)
    same_release = [k for k in cands if eco_parts(k)[0] == wd and eco_parts(k)[2] == wr]
    plain = [k for k in same_release if not eco_parts(k)[1]]
    if plain:
        return (plain[0], True)
    if same_release:
        return (same_release[0], True)
    same_distro = [k for k in cands if eco_parts(k)[0] == wd]
    plain_distro = [k for k in same_distro if not eco_parts(k)[1]]
    if plain_distro:
        return (plain_distro[0], False)
    if same_distro:
        return (same_distro[0], False)
    return ("", False)


def version_verdict(installed: str, eco_map: Optional[Dict[str, List[str]]],
                    want_eco: str) -> Dict[str, str]:
    if not eco_map:
        return {"verdict": "unknown", "target": "", "eco": ""}

    eco, exact = pick_ecosystem(eco_map, want_eco)
    if not eco:
        return {"verdict": "unknown", "target": "", "eco": ""}

    fixes = [f for f in (eco_map.get(eco) or []) if f]
    if not fixes or not installed:
        return {"verdict": "unknown", "target": "", "eco": eco}
    try:
        branch = _series(installed)
        same = [f for f in fixes if branch and _series(f) == branch]
        pool = same or fixes
        if any(cmp_version(installed, f) >= 0 for f in pool):
            if not exact:
                return {"verdict": "unknown", "target": "", "eco": eco}
            return {"verdict": "fixed", "target": "", "eco": eco}
        target = sorted(pool, key=functools.cmp_to_key(cmp_version))[0]
        return {"verdict": "vulnerable", "target": target, "eco": eco}
    except Exception:
        return {"verdict": "unknown", "target": fixes[0], "eco": eco}


def parse_sbom_csv(path: str) -> List[Dict]:
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


def index_sbom(rows: List[Dict], kernel_aliases: Optional[set] = None) -> Dict[str, Dict]:
    aliases = kernel_aliases or set()
    keys: Dict[str, Dict] = {}
    for r in rows:
        for cand in (r.get("source"), r.get("name")):
            if not cand:
                continue
            low = cand.lower()
            for k in (low, norm_pkg(cand)):
                if k and k not in keys:
                    keys[k] = r
            if low in aliases and "linux" not in keys:
                keys["linux"] = r
    return keys


def sbom_match(cve: Dict, keys: Dict[str, Dict], pkg_index: Dict) -> Optional[Dict]:
    pkg_map = pkg_index.get(cve.get("id")) or {}
    for p in pkg_map:
        hit = keys.get(str(p).lower()) or keys.get(norm_pkg(p))
        if hit:
            v = version_verdict(hit.get("version", ""), pkg_map[p], sbom_ecosystem(hit))
            return {"row": hit, "via": "osv", "pkg": p, **v}
    for a in (cve.get("affected") or []):
        prod = a.get("product") or ""
        if not prod:
            continue
        hit = keys.get(prod.lower()) or keys.get(norm_pkg(prod))
        if hit:
            return {"row": hit, "via": "name", "pkg": prod,
                    "verdict": "unknown", "target": "", "eco": ""}
    return None


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
    kernel_aliases = {str(n).lower() for n in
                      (pkg_doc.get("kernel_aliases") or [] if isinstance(pkg_doc, dict) else [])}
    cves = cve_doc if isinstance(cve_doc, list) else (cve_doc.get("cves") or [])
    info(f"추적 CVE {len(cves):,}건 · 패키지 인덱스 {len(pkg_index):,}건"
         + (f" · 커널 별칭 {len(kernel_aliases)}종" if kernel_aliases else ""))

    keys = index_sbom(rows, kernel_aliases)
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
