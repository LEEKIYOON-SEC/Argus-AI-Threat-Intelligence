"""
공유 위협 인텔리전스 소스 (P5 데이터 소스 확대)

collector와 rule_manager가 함께 쓰는 저비용 인덱스 소스를 한 곳에서 관리한다:
- 디스크 캐시 헬퍼 (24h TTL) — 룰셋/인덱스 매시간 재다운로드 방지
- ExploitDB files_exploits.csv 매핑 → has_public_exploit 신호 (P2에서 구축한 캐시 재활용)
- Metasploit modules_metadata_base.json → has_metasploit_module "무기화됨" 신호 (BSD-3-Clause)

라이선스:
- ExploitDB: 개별 PoC 저작권은 각 제출자. 원문 재게시 금지, 링크만 (불변 원칙 8-②).
  여기서는 CVE→파일 매핑(사실 정보)과 boolean 신호만 다룬다.
- Metasploit metadata: BSD-3-Clause. 모듈명·CVE 참조는 사실 메타데이터.
  재게시 시 출처(Metasploit Framework, Rapid7) 표기.
- nuclei-templates: MIT (ProjectDiscovery, Inc.). CVE→템플릿 매핑과 템플릿 경로만 쓴다.
  재게시 시 출처 표기. 템플릿이 있다는 것은 "누구나 대량 스캔·검증할 수 있다"는 뜻이라
  탐지 룰인 동시에 무기화 신호다.
- CISA KEV: U.S. Government Work (퍼블릭 도메인). 제한 없음.
- VulnCheck KEV: 무료. **"prominent attribution to VulnCheck" 표기 의무**가 있으므로
  이 신호가 알림·리포트에 쓰일 때는 반드시 출처를 함께 싣는다.
"""

import csv
import io
import json
import os
import re
import threading
import time
from typing import Dict, List, Optional, Tuple

import requests

from logger import logger
from rate_limiter import rate_limit_manager

# ─────────────────────────────────────────────
# 디스크 캐시 (24h TTL) — rule_manager와 동일 디렉토리·키를 공유해 중복 다운로드 방지
# ─────────────────────────────────────────────
_CACHE_DIR = os.environ.get(
    "ARGUS_CACHE_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".cache", "rulesets")
)
_CACHE_TTL_HOURS = 24

EXPLOITDB_RAW_BASE = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/"
_METASPLOIT_URL = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
_NUCLEI_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json"
_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_VULNCHECK_KEV_URL = "https://api.vulncheck.com/v3/index/vulncheck-kev"

_lock = threading.Lock()


def cache_get(name: str, ttl_hours: int = _CACHE_TTL_HOURS) -> Optional[bytes]:
    path = os.path.join(_CACHE_DIR, name)
    try:
        if os.path.exists(path):
            age = time.time() - os.path.getmtime(path)
            if age < ttl_hours * 3600:
                with open(path, "rb") as f:
                    return f.read()
    except OSError as e:
        logger.debug(f"캐시 읽기 실패 ({name}): {e}")
    return None


def cache_put(name: str, content: bytes) -> None:
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        path = os.path.join(_CACHE_DIR, name)
        with open(path, "wb") as f:
            f.write(content)
    except OSError as e:
        logger.debug(f"캐시 쓰기 실패 ({name}): {e}")


# ─────────────────────────────────────────────
# ExploitDB — CVE → (파일 경로, EDB-ID)
# ─────────────────────────────────────────────
_exploitdb_index: Dict[str, Tuple[str, str]] = {}
_exploitdb_loaded = False
_CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)


def load_exploitdb_index() -> Dict[str, Tuple[str, str]]:
    """files_exploits.csv(캐시)에서 CVE→exploit 파일 매핑 구축"""
    global _exploitdb_loaded
    with _lock:
        if _exploitdb_loaded:
            return _exploitdb_index
        _exploitdb_loaded = True

        raw = cache_get("exploitdb-files.csv")
        if raw is None:
            logger.info("📥 Exploit-DB CSV 인덱스 다운로드 중...")
            try:
                rate_limit_manager.check_and_wait("ruleset_download")
                response = requests.get(EXPLOITDB_RAW_BASE + "files_exploits.csv", timeout=60)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("exploitdb-files.csv", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ Exploit-DB CSV 다운로드 실패: {e}")
                return _exploitdb_index
        else:
            logger.info("📥 Exploit-DB CSV 인덱스 캐시 로드")

        try:
            reader = csv.DictReader(io.StringIO(raw.decode('utf-8', errors='ignore')))
            for row in reader:
                codes = row.get("codes", "") or ""
                file_path = row.get("file", "") or ""
                edb_id = row.get("id", "") or ""
                if not file_path:
                    continue
                for cve in _CVE_RE.findall(codes):
                    _exploitdb_index.setdefault(cve.upper(), (file_path, edb_id))
            logger.info(f"  ✅ Exploit-DB 인덱스 로드 완료 ({len(_exploitdb_index)}개 CVE 매핑)")
        except Exception as e:
            logger.warning(f"  ⚠️ Exploit-DB CSV 파싱 실패: {e}")

    return _exploitdb_index


def exploitdb_entry(cve_id: str) -> Optional[Tuple[str, str]]:
    """CVE에 매핑된 (exploit 파일 경로, EDB-ID) 반환"""
    load_exploitdb_index()
    return _exploitdb_index.get(cve_id.upper())


# ─────────────────────────────────────────────
# Metasploit — CVE → 모듈 메타데이터 (BSD-3-Clause)
# ─────────────────────────────────────────────
_msf_index: Dict[str, List[Dict]] = {}
_msf_loaded = False

# Metasploit 랭크: 값이 높을수록 신뢰도 높음
_MSF_RANK_NAMES = {
    0: "manual", 100: "low", 200: "average", 300: "normal",
    400: "good", 500: "great", 600: "excellent",
}


def load_metasploit_index() -> Dict[str, List[Dict]]:
    """modules_metadata_base.json(캐시)에서 CVE→모듈 매핑 구축"""
    global _msf_loaded
    with _lock:
        if _msf_loaded:
            return _msf_index
        _msf_loaded = True

        raw = cache_get("metasploit-modules.json")
        if raw is None:
            logger.info("📥 Metasploit 메타데이터 다운로드 중...")
            try:
                rate_limit_manager.check_and_wait("ruleset_download")
                response = requests.get(_METASPLOIT_URL, timeout=60)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("metasploit-modules.json", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ Metasploit 메타데이터 다운로드 실패: {e}")
                return _msf_index
        else:
            logger.info("📥 Metasploit 메타데이터 캐시 로드")

        try:
            data = json.loads(raw.decode('utf-8', errors='ignore'))
            for _path, meta in data.items():
                refs = meta.get("references", []) or []
                cves = set()
                for ref in refs:
                    if isinstance(ref, str):
                        # "CVE-2021-1234" 또는 "CVE,2021-1234" 형태 모두 대응
                        for m in _CVE_RE.findall(ref.replace(",", "-")):
                            cves.add(m.upper())
                if not cves:
                    continue
                rank = meta.get("rank", 0)
                entry = {
                    "fullname": meta.get("fullname", meta.get("name", "")),
                    "rank": rank,
                    "rank_name": _MSF_RANK_NAMES.get(rank, str(rank)),
                    "type": meta.get("type", ""),
                }
                for cve in cves:
                    _msf_index.setdefault(cve, []).append(entry)
            logger.info(f"  ✅ Metasploit 인덱스 로드 완료 ({len(_msf_index)}개 CVE 매핑)")
        except Exception as e:
            logger.warning(f"  ⚠️ Metasploit 메타데이터 파싱 실패: {e}")

    return _msf_index


def metasploit_modules(cve_id: str) -> List[Dict]:
    """CVE에 매핑된 Metasploit 모듈 목록 (신뢰도 높은 순).
    비어 있으면 무기화 신호 없음 — 호출측이 bool()로 판별한다."""
    load_metasploit_index()
    mods = _msf_index.get(cve_id.upper(), [])
    return sorted(mods, key=lambda m: m.get("rank", 0), reverse=True)


# ─────────────────────────────────────────────
# nuclei-templates — CVE → 템플릿 (MIT, ProjectDiscovery)
#
# 탐지 룰이면서 동시에 무기화 신호다. 템플릿이 올라왔다는 건 "공격 조건이 재현 가능한
# 형태로 정리돼 누구나 대량 스캔할 수 있다"는 뜻이라, KEV 등재보다 앞서는 경우가 많다.
# cves.json은 JSON Lines(줄마다 객체 하나)이며 실측 4,363건 / 2.1MB.
# ─────────────────────────────────────────────
_nuclei_index: Dict[str, Dict] = {}
_nuclei_loaded = False


def load_nuclei_index() -> Dict[str, Dict]:
    """cves.json(캐시)에서 CVE→템플릿 메타 구축."""
    global _nuclei_loaded
    with _lock:
        if _nuclei_loaded:
            return _nuclei_index
        _nuclei_loaded = True

        raw = cache_get("nuclei-cves.json")
        if raw is None:
            logger.info("📥 nuclei-templates 인덱스 다운로드 중...")
            try:
                rate_limit_manager.check_and_wait("ruleset_download")
                response = requests.get(_NUCLEI_URL, timeout=60)
                response.raise_for_status()
                rate_limit_manager.record_call("ruleset_download")
                raw = response.content
                cache_put("nuclei-cves.json", raw)
            except Exception as e:
                logger.warning(f"  ⚠️ nuclei-templates 다운로드 실패: {e}")
                return _nuclei_index
        else:
            logger.info("📥 nuclei-templates 인덱스 캐시 로드")

        for line in raw.decode("utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            cve_id = str(obj.get("ID") or "").upper()
            if not cve_id.startswith("CVE-"):
                continue
            info = obj.get("Info") or {}
            _nuclei_index[cve_id] = {
                "name": info.get("Name", ""),
                "severity": info.get("Severity", ""),
                "path": obj.get("file_path", ""),
            }
        logger.info(f"  ✅ nuclei-templates 인덱스 로드 완료 ({len(_nuclei_index)}개 CVE 매핑)")

    return _nuclei_index


def nuclei_template(cve_id: str) -> Optional[Dict]:
    """CVE에 매핑된 nuclei 템플릿 메타. 없으면 None."""
    load_nuclei_index()
    return _nuclei_index.get(cve_id.upper())


def nuclei_template_url(path: str) -> str:
    """템플릿 경로 → 저장소 URL (원문은 재게시하지 않고 링크만 싣는다)."""
    return f"https://github.com/projectdiscovery/nuclei-templates/blob/main/{path}"


# ─────────────────────────────────────────────
# KEV 목록 — 스냅샷 대조가 '전량 집합'으로 쓴다
# ─────────────────────────────────────────────
def load_cisa_kev(ttl_hours: int = 1) -> Optional[Dict[str, Dict]]:
    """CISA KEV 전량 → {CVE: 항목}. 실패하면 None.

    None과 빈 dict를 구분하는 게 중요하다 — 스냅샷 대조에서 '수신 실패'를 '전부 사라짐'으로
    읽으면 다음 실행에서 전량이 신규로 보여 알림 폭풍이 난다.
    TTL이 짧은 이유: 이 목록의 변화가 곧 T0 알림이라 캐시로 지연시키면 안 된다."""
    raw = cache_get("cisa-kev.json", ttl_hours=ttl_hours)
    if raw is None:
        try:
            rate_limit_manager.check_and_wait("kev")
            response = requests.get(_CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            rate_limit_manager.record_call("kev")
            raw = response.content
            cache_put("cisa-kev.json", raw)
        except Exception as e:
            logger.error(f"CISA KEV 수신 실패: {e}")
            return None
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except ValueError as e:
        logger.error(f"CISA KEV 파싱 실패: {e}")
        return None
    out = {}
    for item in data.get("vulnerabilities", []) or []:
        cve_id = item.get("cveID")
        if cve_id:
            out[cve_id.upper()] = item
    logger.info(f"📥 CISA KEV {len(out)}건")
    return out


def load_vulncheck_kev(ttl_hours: int = 1) -> Optional[Dict[str, Dict]]:
    """VulnCheck KEV 전량 → {CVE: 항목}. 키가 없거나 실패하면 None.

    CISA KEV보다 넓고 대체로 이르다. 무료지만 **출처 표기 의무**가 있어,
    이 신호로 알림이 나갈 때는 'VulnCheck KEV'를 반드시 함께 싣는다."""
    api_key = os.environ.get("VULNCHECK_API_KEY")
    if not api_key:
        logger.debug("VULNCHECK_API_KEY 미설정 → VulnCheck KEV 건너뜀")
        return None

    raw = cache_get("vulncheck-kev.json", ttl_hours=ttl_hours)
    if raw is None:
        try:
            rate_limit_manager.check_and_wait("vulncheck")
            response = requests.get(
                _VULNCHECK_KEV_URL,
                headers={"Authorization": f"Bearer {api_key}", "Accept": "application/json"},
                params={"limit": 10000},
                timeout=60,
            )
            response.raise_for_status()
            rate_limit_manager.record_call("vulncheck")
            raw = response.content
            cache_put("vulncheck-kev.json", raw)
        except Exception as e:
            logger.warning(f"VulnCheck KEV 수신 실패: {e}")
            return None
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except ValueError as e:
        logger.warning(f"VulnCheck KEV 파싱 실패: {e}")
        return None
    out = {}
    for item in data.get("data", []) or []:
        cve_id = item.get("cveID") or item.get("cve_id")
        # cve가 배열로 오는 스키마 변형도 받아 준다
        if not cve_id:
            arr = item.get("cve") or []
            cve_id = arr[0] if isinstance(arr, list) and arr else None
        if cve_id:
            out[str(cve_id).upper()] = item
    logger.info(f"📥 VulnCheck KEV {len(out)}건 (출처 표기 의무 있음)")
    return out


# ─────────────────────────────────────────────
# EPSS 전량 덤프 — 점수와 percentile을 함께 읽는다
#
# percentile이 중요한 이유는 risk.py 주석에 있다: 절대 점수는 EPSS 모델이 갱신되면
# 같은 값의 의미가 달라지지만 percentile은 분포 기준이라 그렇지 않다.
# 출처 표기 요청이 있는 소스다 (FIRST.org).
# ─────────────────────────────────────────────
_EPSS_CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def load_epss_full(ttl_hours: int = 6) -> Optional[Dict[str, Tuple[float, float]]]:
    """EPSS 전량 → {CVE: (score, percentile)}. 실패하면 None.

    실측 366,357건 / gz 2.5MB. 정방향 API(CVE를 주고 점수를 받는)와 달리 '전량'이라,
    '점수가 높은 CVE 전체'를 우리 DB와 대조하는 역방향 사용이 가능하다."""
    import gzip

    raw = cache_get("epss-full.csv.gz", ttl_hours=ttl_hours)
    if raw is None:
        try:
            rate_limit_manager.check_and_wait("epss")
            response = requests.get(_EPSS_CURRENT_URL, timeout=120, allow_redirects=True)
            response.raise_for_status()
            rate_limit_manager.record_call("epss")
            raw = response.content
            cache_put("epss-full.csv.gz", raw)
            logger.info(f"📥 EPSS 전량 덤프 수신 ({len(raw) / 1024 / 1024:.1f}MB)")
        except Exception as e:
            logger.warning(f"EPSS 전량 덤프 수신 실패: {e}")
            return None
    else:
        logger.info("📥 EPSS 전량 덤프 캐시 로드")

    try:
        text = gzip.decompress(raw).decode("utf-8", errors="replace")
    except Exception as e:
        logger.warning(f"EPSS 덤프 압축 해제 실패: {e}")
        return None

    out: Dict[str, Tuple[float, float]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("cve,"):
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        try:
            out[parts[0].upper()] = (float(parts[1]), float(parts[2]))
        except ValueError:
            continue
    logger.info(f"  ✅ EPSS {len(out):,}건 (점수 + percentile)")
    return out


def load_epss_above(min_percentile: float) -> Optional[Dict[str, Tuple[float, float]]]:
    """EPSS 전량 중 percentile이 임계 이상인 것만. 실패하면 None.

    fast-lane이 판정에만 쓰려고 366,357건을 통째로 메모리에 드는 것을 피하기 위한 것이다.
    임계 미만은 어차피 어떤 EPSS 트리거도 켜지 못하므로(risk.EPSS_P_HIGH가 하한),
    없는 것과 판정 결과가 같다. 실측 p90 이상은 36,636건으로 1/10이다.

    주의: 여기 없는 CVE의 '표시용 정확한 점수'는 0이 아니라 **모름**이다. 추적이 확정된
    소수에 대해서만 Collector.fetch_epss로 정확한 값을 채운다."""
    full = load_epss_full()
    if full is None:
        return None
    out = {cve: v for cve, v in full.items() if v[1] >= min_percentile}
    logger.info(f"  EPSS p{min_percentile:.0%} 이상 {len(out):,}건만 유지")
    return out
