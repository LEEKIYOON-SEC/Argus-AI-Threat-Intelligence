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


def has_public_exploit(cve_id: str) -> bool:
    """ExploitDB에 공개 익스플로잇이 존재하는지 (1급 위험 신호)"""
    return exploitdb_entry(cve_id) is not None


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
    """CVE에 매핑된 Metasploit 모듈 목록 (신뢰도 높은 순)"""
    load_metasploit_index()
    mods = _msf_index.get(cve_id.upper(), [])
    return sorted(mods, key=lambda m: m.get("rank", 0), reverse=True)


def has_metasploit_module(cve_id: str) -> bool:
    """Metasploit 모듈이 존재하는지 ("무기화됨" 신호)"""
    load_metasploit_index()
    return cve_id.upper() in _msf_index
