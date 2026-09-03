import io
import json
import os
import re
import zipfile
from typing import Dict, Iterable, List, Set, Tuple

import requests

from logger import logger

_BASE = "https://storage.googleapis.com/osv-vulnerabilities"

ECOSYSTEMS = [
    "Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux",
    "SUSE", "openSUSE", "Chainguard", "Wolfi",
    "npm", "PyPI", "Maven", "Go", "NuGet", "RubyGems", "Packagist",
    "crates.io", "Hex", "Pub",
    "Bitnami",
    "GitHub Actions",
]

_TIMEOUT = 180


FAILED_ECOSYSTEMS: Set[str] = set()
MAX_FAILED_RATIO = 0.2


def _iter_vulns(eco: str) -> Iterable[dict]:
    url = f"{_BASE}/{eco}/all.zip"
    logger.info(f"  OSV 덤프 내려받는 중: {eco}")
    try:
        resp = requests.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.warning(f"  OSV {eco} 다운로드 실패 → 이 생태계 생략: {e}")
        FAILED_ECOSYSTEMS.add(eco)
        return

    try:
        with zipfile.ZipFile(io.BytesIO(resp.content)) as z:
            names = [n for n in z.namelist() if n.endswith(".json")]
            logger.info(f"  {eco}: {len(names):,}건 파싱")
            for name in names:
                try:
                    yield json.loads(z.read(name))
                except (ValueError, KeyError):
                    continue
    except zipfile.BadZipFile as e:
        logger.warning(f"  OSV {eco} 압축 해제 실패 → 생략: {e}")
        FAILED_ECOSYSTEMS.add(eco)


def too_many_failed(ecosystems: List[str] = None) -> bool:
    total = len(ecosystems or ECOSYSTEMS)
    failed = len(FAILED_ECOSYSTEMS & set(ecosystems or ECOSYSTEMS))
    if failed and failed > total * MAX_FAILED_RATIO:
        logger.error(f"OSV 생태계 {failed}/{total}개를 못 받았다 "
                     f"({', '.join(sorted(FAILED_ECOSYSTEMS))}) — 기존 인덱스를 덮어쓰지 않는다")
        return True
    if failed:
        logger.warning(f"OSV 생태계 {failed}/{total}개 누락: "
                       f"{', '.join(sorted(FAILED_ECOSYSTEMS))}")
    return False


def _cve_aliases(rec: dict) -> Set[str]:
    cand = [rec.get("id", "")]
    cand += rec.get("upstream") or []
    cand += rec.get("aliases") or []
    return {c for c in cand if isinstance(c, str) and c.startswith("CVE-")}


def _fixed_versions(aff: dict) -> List[str]:
    out = set()
    for rng in aff.get("ranges") or []:
        for ev in rng.get("events") or []:
            f = ev.get("fixed")
            if f:
                out.add(str(f))
    return sorted(out)


def _vkey(v: str):
    return [(0, int(x)) if x.isdigit() else (1, x)
            for x in re.split(r'(\d+)', str(v or '')) if x]


_MAX_FIXED = 10


def _fold_kernel_flavors(index: Dict[str, Dict[str, Dict[str, List[str]]]]) -> Set[str]:
    aliases: Set[str] = set()
    for pkgs in index.values():
        base = pkgs.get("linux")
        if base is None:
            continue
        if not any(f for fixes in base.values() for f in (fixes or [])):
            continue
        variants = [p for p in pkgs if p != "linux" and p.startswith("linux-")]
        for p in variants:
            del pkgs[p]
        aliases.update(variants)
    return aliases


def build_index(cve_ids: Iterable[str], ecosystems: List[str] = None
                ) -> Tuple[Dict[str, Dict[str, Dict[str, List[str]]]], List[str]]:
    wanted = {c for c in cve_ids if c}
    if not wanted:
        return {}, []

    index: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
    for eco in (ecosystems or ECOSYSTEMS):
        hits = 0
        for rec in _iter_vulns(eco):
            if str(rec.get("id", "")).startswith("MAL-"):
                continue
            cves = _cve_aliases(rec) & wanted
            if not cves:
                continue
            for aff in rec.get("affected") or []:
                pkg_info = aff.get("package") or {}
                pkg = pkg_info.get("name")
                if not pkg:
                    continue
                pkg_eco = pkg_info.get("ecosystem") or eco
                fixes = [f for f in _fixed_versions(aff) if f]
                for c in cves:
                    slot = index.setdefault(c, {}).setdefault(pkg, {})
                    if not fixes:
                        continue
                    merged = sorted(set(slot.get(pkg_eco) or []) | set(fixes), key=_vkey)
                    slot[pkg_eco] = merged[:_MAX_FIXED]
                    hits += 1
        logger.info(f"  {eco}: 매칭 {hits:,}건")

    aliases = sorted(_fold_kernel_flavors(index))
    if aliases:
        logger.info(f"  커널 변종 {len(aliases):,}종을 'linux'로 접음 (별칭으로 함께 배포)")

    with_fix = sum(1 for pkgs in index.values()
                   for ecos in pkgs.values() if any(ecos.values()))
    logger.info(f"OSV 역인덱스: CVE {len(index):,}개에 패키지명 부여 "
                f"(추적 {len(wanted):,}건 중 {len(index) / max(len(wanted), 1) * 100:.0f}%) "
                f"· 수정 버전 보유 {with_fix:,}개 항목")
    return index, aliases


MALICIOUS_ECOSYSTEMS = ["npm", "PyPI"]


def build_malicious_index(ecosystems: List[str] = None) -> List[str]:
    names: Set[str] = set()
    for eco in (ecosystems or MALICIOUS_ECOSYSTEMS):
        before = len(names)
        for rec in _iter_vulns(eco):
            if not str(rec.get("id", "")).startswith("MAL-"):
                continue
            for aff in rec.get("affected") or []:
                nm = (aff.get("package") or {}).get("name")
                if nm:
                    names.add(str(nm).lower())
        logger.info(f"  {eco}: 악성 패키지 {len(names) - before:,}개")
    logger.info(f"OSV 악성 패키지 목록: {len(names):,}개")
    return sorted(names)


def write_malicious(names: List[str], path: str) -> bool:
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = {
            "_source": "OSV.dev (Open Source Vulnerabilities) — malicious packages",
            "_license": "CC-BY 4.0",
            "_url": "https://osv.dev",
            "_note": "이름 일치는 '확인 필요' 신호이며 감염 확정이 아니다",
            "names": names,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
        logger.info(f"악성 패키지 목록 저장: {path} "
                    f"({os.path.getsize(path) / 1024 / 1024:.1f} MB · {len(names):,}개)")
        return True
    except OSError as e:
        logger.error(f"악성 패키지 목록 저장 실패: {e}")
        return False


def write_index(index: Dict, path: str, kernel_aliases: Iterable[str] = ()) -> bool:
    try:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        payload = {
            "_source": "OSV.dev (Open Source Vulnerabilities)",
            "_license": "CC-BY 4.0",
            "_url": "https://osv.dev",
            "schema": 3,
            "kernel_aliases": sorted(kernel_aliases),
            "packages": index,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
        size = os.path.getsize(path) / 1024
        logger.info(f"역인덱스 저장: {path} ({size:,.0f} KB)")
        return True
    except OSError as e:
        logger.error(f"역인덱스 저장 실패: {e}")
        return False
