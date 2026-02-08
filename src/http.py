from __future__ import annotations

import logging
import time
from typing import Dict, Optional

import requests
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

log = logging.getLogger("argus.http")

DEFAULT_UA = "Argus-AI-Threat-Intelligence/1.0"


class HttpError(RuntimeError):
    pass


def _default_headers(extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {
        "User-Agent": DEFAULT_UA,
        "Accept": "*/*",
    }
    if extra:
        h.update(extra)
    return h


@retry(
    reraise=True,
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1, min=1, max=12),
    retry=retry_if_exception_type((requests.Timeout, requests.ConnectionError)),
)
def http_get(
    url: str,
    timeout: int = 60,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> bytes:
    """
    공통 다운로드 함수.
    - Timeout/ConnectionError는 재시도
    - HTTP 4xx/5xx는 즉시 실패(재시도하지 않음)
    """
    h = _default_headers(headers)
    t0 = time.time()
    resp = requests.get(url, headers=h, timeout=timeout, allow_redirects=allow_redirects)
    dt = time.time() - t0

    if resp.status_code >= 400:
        raise HttpError(f"HTTP {resp.status_code} for {url} :: {resp.text[:300]}")

    log.info("GET %s (%d bytes, %.2fs)", url, len(resp.content), dt)
    return resp.content


def http_get_json(
    url: str,
    timeout: int = 60,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> dict:
    b = http_get(url, timeout=timeout, headers=headers, allow_redirects=allow_redirects)
    try:
        return requests.models.complexjson.loads(b.decode("utf-8", errors="strict"))
    except Exception as e:
        raise HttpError(f"JSON decode failed for {url}: {e}") from e
