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


def build_index(cve_ids: Iterable[str],
                ecosystems: List[str] = None) -> Dict[str, List[str]]:
    """추적 중인 CVE에 대해서만 {CVE: [패키지명]} 역인덱스를 만든다.

    전량을 담으면 커밋되는 파일이 수 MB 늘어난다. 대시보드에 없는 CVE는 대조할 일도
    없으므로 우리가 가진 목록으로 좁힌다."""
    wanted = {c for c in cve_ids if c}
    if not wanted:
        return {}

    index: Dict[str, Set[str]] = {}
    for eco in (ecosystems or ECOSYSTEMS):
        hits = 0
        for rec in _iter_vulns(eco):
            cves = _cve_aliases(rec) & wanted
            if not cves:
                continue
            for aff in rec.get("affected") or []:
                pkg = (aff.get("package") or {}).get("name")
                if not pkg:
                    continue
                for c in cves:
                    index.setdefault(c, set()).add(pkg)
                    hits += 1
        logger.info(f"  {eco}: 매칭 {hits:,}건")

    out = {c: sorted(p) for c, p in index.items()}
    logger.info(f"OSV 역인덱스: CVE {len(out):,}개에 패키지명 부여 "
                f"(추적 {len(wanted):,}건 중 {len(out) / max(len(wanted), 1) * 100:.0f}%)")
    return out


def write_index(index: Dict[str, List[str]], path: str) -> bool:
    """역인덱스를 JSON으로 저장. 대시보드가 SBOM 대조에 사용한다."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = {
            # 출처·라이선스 고지 (불변 원칙 8-①)
            "_source": "OSV.dev (Open Source Vulnerabilities)",
            "_license": "CC-BY 4.0",
            "_url": "https://osv.dev",
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
