"""OSV 역인덱스 — CVE에 실제 패키지 이름을 붙인다.

CVE 레코드만으로는 SBOM과 대조가 안 된다. 실측(2026-08 공개분 60건 표본)으로
CNA가 CPE를 주는 건 15%뿐이고 CISA ADP는 0%였다. 나머지는 자유 텍스트 벤더/제품명
("Legion of the Bouncy Castle Inc. / BC-JAVA")이라 syft가 뱉는 패키지명과 맞지 않는다.

그래서 방향을 뒤집는다. OSV.dev가 배포판 보안 트래커(Debian DSA, Ubuntu USN,
Alpine secdb)와 GitHub Advisory를 정규화해 "이 CVE는 어느 패키지인가"를 이미 정리해
뒀으므로, 그 전량 덤프를 받아 CVE → 패키지명 역인덱스를 만든다.

자산 정보는 이 과정에 전혀 들어가지 않는다 — 공개 취약점 DB만 가공한다. 실제 대조는
사용자 브라우저가 로컬 SBOM CSV로 수행하므로 패키지 목록이 밖으로 나가지 않는다.

주의: OSV는 **소스 패키지명** 기준이다. 검증 결과 `libcurl4` 0건 / `curl` 68건,
`libssl3` 0건 / `openssl` 43건. SBOM 쪽에서도 소스명을 우선 써야 맞는다.

출처: OSV.dev (Open Source Vulnerabilities) — CC-BY 4.0
"""
import io
import json
import os
import zipfile
from typing import Dict, Iterable, List, Set

import requests

from logger import logger

_BASE = "https://storage.googleapis.com/osv-vulnerabilities"

# 받을 생태계. 크기는 2026-08 기준 all.zip 실측치.
#   Ubuntu(588MB)·npm(209MB)이 크지만 러너 디스크(14GB)와 캐시 한도(10GB) 안이고,
#   덤프는 스캔 후 버린다 — 저장소에 커밋되는 건 수백 KB짜리 역인덱스뿐이다.
ECOSYSTEMS = ["Debian", "Ubuntu", "Alpine", "npm", "PyPI", "Maven", "Go"]

_TIMEOUT = 180


def _iter_vulns(eco: str) -> Iterable[dict]:
    """생태계 덤프를 내려받아 취약점 레코드를 하나씩 흘려보낸다 (메모리 상주 최소화)."""
    url = f"{_BASE}/{eco}/all.zip"
    logger.info(f"  OSV 덤프 내려받는 중: {eco}")
    try:
        resp = requests.get(url, timeout=_TIMEOUT)
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.warning(f"  OSV {eco} 다운로드 실패 → 이 생태계 생략: {e}")
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


def _cve_aliases(rec: dict) -> Set[str]:
    """레코드가 가리키는 CVE 식별자. 스키마 1.7에서 upstream으로 옮겨갔고,
    구 스키마는 aliases를 쓰므로 둘 다 본다."""
    cand = [rec.get("id", "")]
    cand += rec.get("upstream") or []
    cand += rec.get("aliases") or []
    return {c for c in cand if isinstance(c, str) and c.startswith("CVE-")}


def _fixed_versions(aff: dict) -> List[str]:
    """affected 항목의 수정(패치) 버전들. ranges[].events[].fixed에 들어 있다.

    versions 배열(취약한 전체 버전 목록)은 쓰지 않는다 — 수백 개씩 들어 있어 인덱스가
    수십 MB로 불어나는데, 우리에게 필요한 건 '어디까지 올리면 되는가' 하나뿐이다."""
    out = set()
    for rng in aff.get("ranges") or []:
        for ev in rng.get("events") or []:
            f = ev.get("fixed")
            if f:
                out.add(str(f))
    return sorted(out)


_MAX_FIXED = 3   # 생태계당 보관할 수정 버전 수 — 크기 상한


def build_index(cve_ids: Iterable[str],
                ecosystems: List[str] = None) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """추적 중인 CVE의 {CVE: {패키지명: {생태계: [수정버전...]}}} 역인덱스.

    전량을 담으면 커밋되는 파일이 수 MB 늘어난다. 대시보드에 없는 CVE는 대조할 일도
    없으므로 우리가 가진 목록으로 좁힌다. (실측: 9,463건 대상 664KB · 매칭률 59%)

    생태계를 키로 두는 이유: 같은 패키지라도 배포판 릴리스마다 수정 버전이 다르다.
    예) linux → Debian:12는 6.1.25-1, Debian:13은 6.1.11-1. 하나로 합치면 사용자가
    자기 릴리스에 맞는 목표 버전을 고를 수 없다.

    수정 버전을 목록으로 두는 이유: 여기서 하나로 줄이려면 버전 비교가 필요한데,
    문자열 정렬은 1.10 < 1.9로 뒤집힌다. 제대로 비교하려면 dpkg 규칙을 파이썬에도
    구현해야 하고 그러면 브라우저 쪽 비교기와 이중 관리가 된다. 비교는 판정하는
    쪽(대시보드) 한 곳에서만 하고, 여기서는 후보를 그대로 넘긴다."""
    wanted = {c for c in cve_ids if c}
    if not wanted:
        return {}

    index: Dict[str, Dict[str, Dict[str, List[str]]]] = {}
    for eco in (ecosystems or ECOSYSTEMS):
        hits = 0
        for rec in _iter_vulns(eco):
            # npm 덤프의 97%가 악성 패키지(MAL) 레코드다. CVE 별칭이 없어 어차피
            # 걸러지지만, 먼저 쳐내면 불필요한 파싱을 통째로 건너뛴다.
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
                # 레코드의 실제 생태계 문자열(Debian:12 등)을 그대로 쓴다 — 덤프 이름
                # (Debian)만으로는 릴리스를 구분할 수 없다.
                pkg_eco = pkg_info.get("ecosystem") or eco
                fixes = _fixed_versions(aff)
                for c in cves:
                    slot = index.setdefault(c, {}).setdefault(pkg, {})
                    merged = sorted(set(slot.get(pkg_eco) or []) | set(fixes))
                    slot[pkg_eco] = merged[:_MAX_FIXED]
                    hits += 1
        logger.info(f"  {eco}: 매칭 {hits:,}건")

    with_fix = sum(1 for pkgs in index.values()
                   for ecos in pkgs.values() if any(ecos.values()))
    logger.info(f"OSV 역인덱스: CVE {len(index):,}개에 패키지명 부여 "
                f"(추적 {len(wanted):,}건 중 {len(index) / max(len(wanted), 1) * 100:.0f}%) "
                f"· 수정 버전 보유 {with_fix:,}개 항목")
    return index


# 악성 패키지는 언어 생태계에만 존재한다 (배포판 덤프에는 MAL 항목이 0건).
MALICIOUS_ECOSYSTEMS = ["npm", "PyPI"]


def build_malicious_index(ecosystems: List[str] = None) -> List[str]:
    """OSV의 알려진 악성 패키지(MAL-) 이름 목록.

    취약점과 성격이 다르다 — 이건 '고치면 되는 결함'이 아니라 '설치되어 있으면 안 되는
    것'이다. 공급망 공격(타이포스쿼팅·계정 탈취 배포)으로 올라온 패키지들이라 CVE 축과
    별개로 봐야 한다.

    이름만 수집한다. 버전 범위까지 보면 정확도는 오르지만, 화면의 목적이 '확인해 보라'는
    경고이지 확정 판정이 아니라서 이름 일치로 충분하다. (실측: npm 219,640 · PyPI 11,649)
    """
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
    """악성 패키지 이름 목록 저장. 대시보드가 SBOM을 불러올 때만 내려받는다
    (약 5MB — 초기 로드에 얹으면 손해라 지연 로딩한다)."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
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


def write_index(index: Dict, path: str) -> bool:
    """역인덱스를 JSON으로 저장. 대시보드가 SBOM 대조에 사용한다."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {
            # 출처·라이선스 고지 (불변 원칙 8-①)
            "_source": "OSV.dev (Open Source Vulnerabilities)",
            "_license": "CC-BY 4.0",
            "_url": "https://osv.dev",
            # 스키마: {CVE: {패키지명: {생태계: [수정버전...]}}}
            "schema": 2,
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
