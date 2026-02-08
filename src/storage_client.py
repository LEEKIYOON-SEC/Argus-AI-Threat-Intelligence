from __future__ import annotations

import os
import mimetypes
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any

import requests

log = logging.getLogger("argus.storage")


@dataclass
class StorageUploadResult:
    ok: bool
    object_path: str
    bytes: int
    details: str


@dataclass
class SignedURLResult:
    ok: bool
    url: str
    details: str


def _base_url(cfg) -> str:
    url = getattr(cfg, "SUPABASE_URL", None) or os.getenv("SUPABASE_URL", "")
    return url.rstrip("/")


def _service_headers(cfg) -> Dict[str, str]:
    key = getattr(cfg, "SUPABASE_KEY", None) or os.getenv("SUPABASE_KEY", "")
    return {
        "apikey": key,
        "Authorization": f"Bearer {key}",
        "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
    }


def _guess_content_type(path: str, default: str = "application/octet-stream") -> str:
    ct, _ = mimetypes.guess_type(path)
    return ct or default


def upload_bytes(
    cfg,
    *,
    bucket: str,
    object_path: str,
    data: bytes,
    content_type: Optional[str] = None,
    upsert: bool = True,
) -> StorageUploadResult:
    """
    Supabase Storage upload (비용 0, service_role 권장).
    PUT /storage/v1/object/{bucket}/{path}
    """
    base = _base_url(cfg)
    if not base:
        return StorageUploadResult(False, object_path, 0, "SUPABASE_URL missing")

    if data is None:
        return StorageUploadResult(False, object_path, 0, "data is None")

    ct = content_type or _guess_content_type(object_path)
    url = f"{base}/storage/v1/object/{bucket}/{object_path.lstrip('/')}"
    headers = _service_headers(cfg)
    headers["Content-Type"] = ct

    params = {}
    if upsert:
        params["upsert"] = "true"

    try:
        r = requests.put(url, headers=headers, params=params, data=data, timeout=60)
        if r.status_code >= 400:
            return StorageUploadResult(False, object_path, len(data), f"upload_failed {r.status_code}: {r.text[:300]}")
        return StorageUploadResult(True, object_path, len(data), "ok")
    except Exception as e:
        return StorageUploadResult(False, object_path, len(data), f"upload_exception: {e}")


def create_signed_url(
    cfg,
    *,
    bucket: str,
    object_path: str,
    expires_in_seconds: int,
) -> SignedURLResult:
    """
    POST /storage/v1/object/sign/{bucket}/{path}
    returns { signedURL: "/storage/v1/object/sign/..." } 형태.
    """
    base = _base_url(cfg)
    if not base:
        return SignedURLResult(False, "", "SUPABASE_URL missing")

    expires_in_seconds = max(60, int(expires_in_seconds))
    url = f"{base}/storage/v1/object/sign/{bucket}/{object_path.lstrip('/')}"
    headers = _service_headers(cfg)
    headers["Content-Type"] = "application/json"

    try:
        r = requests.post(url, headers=headers, json={"expiresIn": expires_in_seconds}, timeout=30)
        if r.status_code >= 400:
            return SignedURLResult(False, "", f"signed_url_failed {r.status_code}: {r.text[:300]}")

        j: Any = r.json()
        signed = j.get("signedURL") if isinstance(j, dict) else None
        if not isinstance(signed, str) or not signed:
            return SignedURLResult(False, "", f"signed_url_missing_field: {str(j)[:300]}")

        # signedURL은 상대경로로 오는 경우가 많음 → 절대 URL로 변환
        if signed.startswith("http"):
            return SignedURLResult(True, signed, "ok")

        full = base + signed
        return SignedURLResult(True, full, "ok")
    except Exception as e:
        return SignedURLResult(False, "", f"signed_url_exception: {e}")


def delete_object(cfg, *, bucket: str, object_path: str) -> bool:
    """
    DELETE /storage/v1/object/{bucket}/{path}
    """
    base = _base_url(cfg)
    if not base:
        return False

    url = f"{base}/storage/v1/object/{bucket}/{object_path.lstrip('/')}"
    headers = _service_headers(cfg)

    try:
        r = requests.delete(url, headers=headers, timeout=30)
        # 200/204가 일반적. 404도 '이미 없음'으로 성공 처리 가능.
        if r.status_code in (200, 204, 404):
            return True
        log.info("delete_object failed %s %s", r.status_code, r.text[:200])
        return False
    except Exception as e:
        log.info("delete_object exception: %s", e)
        return False
