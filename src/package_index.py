import json
import os
import threading
import urllib.request
from typing import Dict, Optional

import enrichment_sources
from logger import logger

_CACHE_NAME = "cve-packages.json"
_CACHE_TTL_HOURS = 24
_TIMEOUT = 25

_INDEX: Optional[Dict] = None
_LOCK = threading.Lock()


def _parse(payload: bytes) -> Optional[Dict]:
    try:
        return (json.loads(payload.decode("utf-8")) or {}).get("packages") or {}
    except (ValueError, UnicodeDecodeError) as e:
        logger.warning(f"패키지 사전 파싱 실패: {e}")
        return None


def _load() -> Optional[Dict]:
    cached = enrichment_sources.cache_get(_CACHE_NAME, _CACHE_TTL_HOURS)
    if cached is not None:
        idx = _parse(cached)
        if idx is not None:
            logger.info(f"패키지 사전 로드(캐시): {len(idx):,}건")
            return idx

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        url = f"https://{owner.lower()}.github.io/{name}/data/{_CACHE_NAME}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "argus-packages"})
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
                payload = r.read()
            idx = _parse(payload)
            if idx is not None:
                enrichment_sources.cache_put(_CACHE_NAME, payload)
                logger.info(f"패키지 사전 로드(배포본): {len(idx):,}건")
                return idx
        except Exception as e:
            logger.warning(f"패키지 사전 배포본 로드 실패({e}) → 체크아웃 사본 확인")

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "docs", "data", _CACHE_NAME)
    try:
        with open(path, "rb") as f:
            payload = f.read()
    except OSError as e:
        logger.warning(f"패키지 사전을 어디서도 읽지 못했다: {e}")
        return None
    idx = _parse(payload)
    if idx is not None:
        logger.info(f"패키지 사전 로드(파일): {len(idx):,}건")
    return idx


def get() -> Optional[Dict]:
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    with _LOCK:
        if _INDEX is None:
            _INDEX = _load()
    return _INDEX


def fixes_for(cve_id: str) -> Dict:
    idx = get()
    if idx is None:
        return {}
    return idx.get(cve_id) or {}
