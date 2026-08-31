"""CVE ↔ 공개 탐지 룰 역인덱스 생성 — 주 1회 별도 실행.

━━ 왜 인덱스로 바꿨나 ━━

예전 rule_manager는 **CVE 한 건마다** SigmaHQ 전체 파일과 ET Open 룰셋 3종(각 수십 MB)을
정규식으로 선형 스캔했다. 히트율은 실측 1.1%다 — 즉 98.9%의 경우 수십 MB를 훑어 "없음"을
확인하는 데 시간을 썼다. 게다가 그 검색이 매시간 실행의 맨 앞(Step 3)에 있었다.

룰셋은 시간 단위로 바뀌지 않는다. 주 1회 CVE→룰 인덱스를 만들어 두면 조회가 O(1)이 되고,
알림 경로에서 룰 검색이 통째로 빠진다.

━━ 무엇을 담나 ━━

**룰 원문이 아니라 위치만** 담는다. 원문은 Issue를 발행하는 순간에만 받아 오면 되고,
인덱스에 넣으면 파일이 수십 MB로 불어난다. 대신 출처·author·라이선스는 인덱스에
함께 실어, 재게시할 때 고지가 유실되지 않게 한다(불변 원칙 8-①).

━━ 라이선스 (전부 원문 확인) ━━

  SigmaHQ            DRL 1.1        author 표기 보존 의무
  ET Open            MIT            (레거시 SID 1–3464는 GPLv2 — 헤더 고지 보존)
  Snort Community    GPLv2          헤더 고지 보존
  nuclei-templates   MIT            ProjectDiscovery, Inc. 저작권 고지 보존
  Splunk ESCU        Apache-2.0     NOTICE 보존
  YARA Forge         룰별 상이       룰 메타(author·source_url·license_url)를 그대로 보존

Elastic detection-rules는 넣지 않았다. Elastic License 2.0은 source-available이라
서비스 제공에 제한 조항이 있어, 공개 대시보드에 싣기에는 법적 검토 부담이 크다.
"""
import io
import json
import os
import re
import sys
import tarfile
import zipfile
from typing import Dict, List, Optional

import requests

import enrichment_sources
from logger import logger

_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "docs", "data")
_OUT = os.path.join(_DATA, "detection-rules.json")

_CVE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
_TIMEOUT = 180

#: {engine: (라이선스, 표기 문구)}
LICENSES = {
    "sigma": ("DRL 1.1", "SigmaHQ — 재게시 시 원 룰의 author 표기 보존"),
    "nuclei": ("MIT", "nuclei-templates (ProjectDiscovery, Inc.)"),
    "splunk": ("Apache-2.0", "Splunk security_content (ESCU) — NOTICE 보존"),
    "yara": ("룰별 상이", "YARA Forge — 룰 메타의 author·source_url·license_url 보존"),
    "snort2": ("MIT / GPLv2(레거시 SID 1–3464)", "Emerging Threats Open / Snort Community"),
    "snort3": ("MIT / GPLv2(레거시 SID 1–3464)", "Emerging Threats Open / Snort Community"),
    "suricata5": ("MIT", "Emerging Threats Open"),
    "suricata7": ("MIT", "Emerging Threats Open"),
}


def _add(index: Dict[str, List[Dict]], cve: str, entry: Dict) -> None:
    bucket = index.setdefault(cve.upper(), [])
    if not any(e["engine"] == entry["engine"] and e["path"] == entry["path"] for e in bucket):
        bucket.append(entry)


def _github_tarball(owner: str, repo: str, label: str) -> Optional[bytes]:
    """저장소 tarball. GH_TOKEN이 있으면 붙인다(익명 한도 회피)."""
    token = os.environ.get("GH_TOKEN")
    headers = {"User-Agent": "argus-rule-index"}
    if token:
        headers["Authorization"] = f"token {token}"
    url = f"https://api.github.com/repos/{owner}/{repo}/tarball"
    try:
        resp = requests.get(url, headers=headers, timeout=_TIMEOUT)
        resp.raise_for_status()
        logger.info(f"  📥 {label} tarball {len(resp.content) / 1e6:.1f}MB")
        return resp.content
    except requests.exceptions.RequestException as e:
        logger.warning(f"  ⚠️ {label} 다운로드 실패 → 이 소스 생략: {e}")
        return None


# ──────────────────────────────────────────────────────────────────────────
# 소스별 수집
# ──────────────────────────────────────────────────────────────────────────
def collect_sigma(index: Dict[str, List[Dict]]) -> int:
    data = _github_tarball("SigmaHQ", "sigma", "SigmaHQ")
    if data is None:
        return 0
    lic, note = LICENSES["sigma"]
    n = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not (member.isfile() and member.name.endswith(".yml")
                        and "/rules" in member.name):
                    continue
                f = tar.extractfile(member)
                if not f:
                    continue
                text = f.read().decode("utf-8", errors="ignore")
                cves = {c.upper() for c in _CVE.findall(text)}
                if not cves:
                    continue
                path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                for cve in cves:
                    _add(index, cve, {"engine": "sigma", "source": "SigmaHQ",
                                      "license": lic, "note": note, "path": path,
                                      "url": f"https://github.com/SigmaHQ/sigma/blob/master/{path}"})
                    n += 1
    except tarfile.TarError as e:
        logger.warning(f"  ⚠️ SigmaHQ 압축 해제 실패: {e}")
    logger.info(f"  ✅ SigmaHQ: {n}개 매핑")
    return n


def collect_splunk(index: Dict[str, List[Dict]]) -> int:
    data = _github_tarball("splunk", "security_content", "Splunk ESCU")
    if data is None:
        return 0
    lic, note = LICENSES["splunk"]
    n = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar.getmembers():
                if not (member.isfile() and "/detections/" in member.name
                        and member.name.endswith(".yml")):
                    continue
                f = tar.extractfile(member)
                if not f:
                    continue
                text = f.read().decode("utf-8", errors="ignore")
                cves = {c.upper() for c in _CVE.findall(text)}
                if not cves:
                    continue
                path = member.name.split("/", 1)[1] if "/" in member.name else member.name
                for cve in cves:
                    _add(index, cve, {"engine": "splunk", "source": "Splunk ESCU",
                                      "license": lic, "note": note, "path": path,
                                      "url": f"https://github.com/splunk/security_content/blob/develop/{path}"})
                    n += 1
    except tarfile.TarError as e:
        logger.warning(f"  ⚠️ Splunk ESCU 압축 해제 실패: {e}")
    logger.info(f"  ✅ Splunk ESCU: {n}개 매핑")
    return n


_YARA_FORGE = ("https://github.com/YARAHQ/yara-forge/releases/latest/download/"
               "yara-forge-rules-core.zip")


def collect_yara(index: Dict[str, List[Dict]]) -> int:
    """YARA Forge core 패키지. 예전에 쓰던 Yara-Rules/rules를 대체한다.

    교체 이유는 커버리지가 아니라 관리 상태와 라이선스다 — 기존 소스는 수년째 방치돼
    있고 GPL-2.0 단일이라 원 저작자 표기가 남지 않는다. YARA Forge는 룰마다
    author·source_url·license_url을 메타로 보존한다(실측: CVE 참조 룰 129개 전부 보유).
    커버리지 자체는 크지 않다(고유 CVE 68건) — YARA는 파일·메모리 탐지라 CVE 단위로
    붙는 경우가 원래 드물다. 있으면 싣고 없으면 마는 부가 정보로 다룬다."""
    lic, note = LICENSES["yara"]
    try:
        resp = requests.get(_YARA_FORGE, timeout=_TIMEOUT,
                            headers={"User-Agent": "argus-rule-index"})
        resp.raise_for_status()
    except requests.exceptions.RequestException as e:
        logger.warning(f"  ⚠️ YARA Forge 다운로드 실패 → 생략: {e}")
        return 0
    n = 0
    try:
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for name in zf.namelist():
                if not name.endswith(".yar"):
                    continue
                text = zf.read(name).decode("utf-8", errors="ignore")
                for chunk in re.split(r'(?=^rule\s+\w+)', text, flags=re.M):
                    cves = {c.upper() for c in _CVE.findall(chunk)}
                    if not cves:
                        continue
                    m = re.search(r'^rule\s+(\w+)', chunk, re.M)
                    rule_name = m.group(1) if m else "?"
                    src = re.search(r'source_url\s*=\s*"([^"]+)"', chunk)
                    author = re.search(r'author\s*=\s*"([^"]+)"', chunk)
                    rule_lic = re.search(r'license_url\s*=\s*"([^"]+)"', chunk)
                    for cve in cves:
                        _add(index, cve, {
                            "engine": "yara", "source": "YARA Forge",
                            "license": lic, "note": note, "path": rule_name,
                            "url": src.group(1) if src else _YARA_FORGE,
                            "author": author.group(1) if author else "",
                            "license_url": rule_lic.group(1) if rule_lic else "",
                        })
                        n += 1
    except zipfile.BadZipFile as e:
        logger.warning(f"  ⚠️ YARA Forge 해제 실패: {e}")
    logger.info(f"  ✅ YARA Forge: {n}개 매핑")
    return n


def collect_nuclei(index: Dict[str, List[Dict]]) -> int:
    """nuclei 템플릿. 위험 신호(risk.nuclei)로도 쓰이지만 탐지·검증 룰이기도 하다."""
    idx = enrichment_sources.load_nuclei_index()
    lic, note = LICENSES["nuclei"]
    for cve, meta in idx.items():
        path = meta.get("path", "")
        _add(index, cve, {"engine": "nuclei", "source": "nuclei-templates",
                          "license": lic, "note": note, "path": path,
                          "severity": meta.get("severity", ""),
                          "url": enrichment_sources.nuclei_template_url(path)})
    logger.info(f"  ✅ nuclei-templates: {len(idx)}개 매핑")
    return len(idx)


_NETWORK_SOURCES = [
    ("Snort 2.9 Community", "https://www.snort.org/downloads/community/community-rules.tar.gz",
     "community.rules", "snort2"),
    ("Snort 3 Community", "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
     "snort3-community.rules", "snort3"),
    ("Snort 2.9 ET Open", "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules",
     None, "snort2"),
    ("Suricata 5 ET Open", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules",
     None, "suricata5"),
    ("Suricata 7 ET Open", "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules",
     None, "suricata7"),
]


def collect_network(index: Dict[str, List[Dict]]) -> int:
    """Snort/Suricata 룰. 룰 한 줄이 곧 룰 전체라 여기서는 **원문을 그대로 담는다**
    (한 줄이라 용량 부담이 없고, 그러면 발행 시점에 다시 받을 필요가 없다)."""
    total = 0
    for label, url, member_hint, engine in _NETWORK_SOURCES:
        lic, note = LICENSES[engine]
        try:
            resp = requests.get(url, timeout=_TIMEOUT,
                                headers={"User-Agent": "argus-rule-index"})
            if resp.status_code != 200:
                logger.warning(f"  ⚠️ {label} HTTP {resp.status_code} → 생략")
                continue
            if member_hint:
                content = None
                with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member_hint in member.name:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode("utf-8", errors="ignore")
                            break
                if content is None:
                    continue
            else:
                content = resp.text
        except Exception as e:
            logger.warning(f"  ⚠️ {label} 실패 → 생략: {e}")
            continue

        n = 0
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "alert" not in stripped:
                continue
            for cve in {c.upper() for c in _CVE.findall(stripped)}:
                _add(index, cve, {"engine": engine, "source": label,
                                  "license": lic, "note": note,
                                  "path": "", "url": "", "code": stripped})
                n += 1
        total += n
        logger.info(f"  ✅ {label}: {n}개 매핑")
    return total


# ──────────────────────────────────────────────────────────────────────────
def main() -> int:
    logger.info("=" * 60)
    logger.info("CVE ↔ 공개 탐지 룰 역인덱스 생성")
    logger.info("=" * 60)

    index: Dict[str, List[Dict]] = {}
    for fn in (collect_nuclei, collect_sigma, collect_network,
               collect_splunk, collect_yara):
        try:
            fn(index)
        except Exception as e:
            # 한 소스의 장애가 나머지를 막지 않게 한다
            logger.error(f"{fn.__name__} 실패 → 계속 진행: {e}")

    if not index:
        logger.error("수집된 룰이 없습니다 — 기존 파일을 덮어쓰지 않고 종료")
        return 1

    by_engine: Dict[str, int] = {}
    for entries in index.values():
        for e in entries:
            by_engine[e["engine"]] = by_engine.get(e["engine"], 0) + 1

    payload = {
        "_source": "SigmaHQ · Emerging Threats Open · Snort Community · "
                   "nuclei-templates · Splunk ESCU · YARA Forge",
        "_license": "각 소스별 라이선스는 항목의 license 필드 참조 — 재게시 시 "
                    "출처·author·라이선스 고지를 함께 싣는다",
        "schema": 1,
        "engines": by_engine,
        "rules": index,
    }
    os.makedirs(_DATA, exist_ok=True)
    tmp = _OUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    os.replace(tmp, _OUT)
    size = os.path.getsize(_OUT) / 1024
    logger.info(f"역인덱스 저장: {_OUT} ({size:,.0f} KB · CVE {len(index):,}건)")
    logger.info(f"엔진별: {by_engine}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
