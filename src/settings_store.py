from __future__ import annotations

import os
import time
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import requests

log = logging.getLogger("argus.settings_store")

_CACHE: Dict[str, Tuple[float, object]] = {}
_CACHE_TTL_SEC = int(os.getenv("ARGUS_SETTINGS_CACHE_TTL_SEC", "300"))  # 5 min (Actions에서는 사실상 1회 실행)


@dataclass
class TrustedRepo:
    repo_full_name: str
    priority: int


def _headers(cfg) -> dict:
    # SUPABASE_KEY는 service_role 권장(운영 요구사항: RLS/권한 설계)
    key = getattr(cfg, "SUPABASE_KEY", None) or os.getenv("SUPABASE_KEY", "")
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "Accept": "application/json",
        "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
    }


def _base_url(cfg) -> str:
    url = getattr(cfg, "SUPABASE_URL", None) or os.getenv("SUPABASE_URL", "")
    return url.rstrip("/")


def _cache_get(k: str):
    now = time.time()
    it = _CACHE.get(k)
    if not it:
        return None
    ts, val = it
    if now - ts > _CACHE_TTL_SEC:
        return None
    return val


def _cache_set(k: str, val: object):
    _CACHE[k] = (time.time(), val)


def get_setting_text(cfg, key: str) -> Optional[str]:
    """
    argus.settings에서 key의 value(text)를 조회. 없으면 None.
    """
    ck = f"setting:{key}"
    cached = _cache_get(ck)
    if cached is not None:
        return cached  # type: ignore

    base = _base_url(cfg)
    if not base:
        return None

    url = f"{base}/rest/v1/settings"
    params = {"select": "value", "key": f"eq.{key}"}

    try:
        r = requests.get(url, headers=_headers(cfg), params=params, timeout=20)
        if r.status_code >= 400:
            log.info("settings fetch failed: %s %s", r.status_code, r.text[:200])
            return None
        rows = r.json() or []
        if not rows:
            _cache_set(ck, None)
            return None
        val = (rows[0].get("value") or "").strip()
        _cache_set(ck, val)
        return val
    except Exception as e:
        log.info("settings fetch error: %s", e)
        return None


def get_setting_int(cfg, key: str, default: int) -> int:
    v = get_setting_text(cfg, key)
    if v is None:
        return default
    try:
        return int(v.strip())
    except Exception:
        return default


def get_trusted_github_repos(cfg) -> List[TrustedRepo]:
    """
    argus.trusted_github_repos에서 enabled=true 목록을 priority asc로 가져옴.
    """
    ck = "trusted_repos"
    cached = _cache_get(ck)
    if cached is not None:
        return cached  # type: ignore

    base = _base_url(cfg)
    if not base:
        return []

    url = f"{base}/rest/v1/trusted_github_repos"
    params = {
        "select": "repo_full_name,priority",
        "enabled": "eq.true",
        "order": "priority.asc",
    }

    try:
        r = requests.get(url, headers=_headers(cfg), params=params, timeout=20)
        if r.status_code >= 400:
            log.info("trusted repos fetch failed: %s %s", r.status_code, r.text[:200])
            return []
        rows = r.json() or []
        out: List[TrustedRepo] = []
        for row in rows:
            repo = (row.get("repo_full_name") or "").strip()
            if not repo:
                continue
            pr = row.get("priority")
            try:
                pr_i = int(pr)
            except Exception:
                pr_i = 100
            out.append(TrustedRepo(repo_full_name=repo, priority=pr_i))
        _cache_set(ck, out)
        return out
    except Exception as e:
        log.info("trusted repos fetch error: %s", e)
        return []
