from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Tuple

from .storage_client import upload_bytes, create_signed_url
from .util.textutil import sha256_hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ym_prefix(dt: datetime) -> str:
    return f"{dt.year:04d}/{dt.month:02d}"


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name, "true" if default else "false").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


def store_report_and_get_link(
    cfg,
    db,
    *,
    cve_id: str,
    alert_type: str,
    notify_reason: str,
    report_md: str,
    kev_listed: bool,
    rules_zip_bytes: Optional[bytes],
) -> Tuple[str, Optional[str], Optional[str], str, str, str]:
    """
    반환: (report_link, report_path, rules_zip_path, report_sha, rules_sha, content_hash)

    - report_link: Slack에 넣을 Signed URL (USE_STORAGE=true 기준)
    - report_path / rules_zip_path: Storage object_path (메타)
    - report_sha / rules_sha: 내용 해시
    - content_hash: 알림 중복방지에 쓰는 최종 페이로드 요약 해시(여기서는 report+zip sha 조합)
    """
    use_storage = _bool_env("USE_STORAGE", True) or bool(getattr(cfg, "USE_STORAGE", False))
    bucket = os.getenv("STORAGE_BUCKET", "") or getattr(cfg, "STORAGE_BUCKET", "argus")

    ttl_days = getattr(cfg, "REPORT_TTL_DAYS", None)
    if ttl_days is None:
        ttl_days = _int_env("REPORT_TTL_DAYS", 30)
    ttl_days = max(1, int(ttl_days))
    expires_sec = ttl_days * 24 * 60 * 60

    now = _utcnow()
    prefix = _ym_prefix(now)

    report_bytes = (report_md or "").encode("utf-8")
    report_sha = sha256_hex(report_bytes)
    rules_sha = sha256_hex(rules_zip_bytes) if rules_zip_bytes else ""

    # content_hash는 dedup/재알림 판단에 활용 가능
    content_hash = sha256_hex((report_sha + "|" + rules_sha + "|" + alert_type + "|" + (notify_reason or "")).encode("utf-8"))

    if not use_storage:
        # Storage를 쓰지 않는 모드: 링크는 비워두고(혹은 텍스트 자체 Slack) -> 이 프로젝트는 링크 기반이 목표라 빈 값
        return "(storage disabled)", None, None, report_sha, rules_sha, content_hash

    # Storage object paths
    # 너무 길지 않게, 규칙적 구조로
    report_path = f"reports/{prefix}/{cve_id}/{cve_id}_{alert_type}.md"
    rules_zip_path = f"rules/{prefix}/{cve_id}/{cve_id}_{alert_type}_rules.zip" if rules_zip_bytes else None

    # 1) upload report
    up1 = upload_bytes(cfg, bucket=bucket, object_path=report_path, data=report_bytes, content_type="text/markdown; charset=utf-8", upsert=True)
    if not up1.ok:
        # 업로드 실패 시 운영이 멈추지 않게 “최소 링크” 대신 에러 표시
        return f"(report upload failed: {up1.details})", report_path, rules_zip_path, report_sha, rules_sha, content_hash

    # 2) upload rules.zip (optional)
    if rules_zip_bytes and rules_zip_path:
        up2 = upload_bytes(cfg, bucket=bucket, object_path=rules_zip_path, data=rules_zip_bytes, content_type="application/zip", upsert=True)
        # rules.zip 실패는 report 링크라도 보내기 위해 치명적 실패로 취급하지 않음
        if not up2.ok:
            rules_zip_path = None

    # 3) signed url for report
    su = create_signed_url(cfg, bucket=bucket, object_path=report_path, expires_in_seconds=expires_sec)
    report_link = su.url if su.ok else f"(signed url failed: {su.details})"

    # 4) DB 메타 저장(감사/정리 기반)
    # db는 SupabaseDB wrapper라고 가정: upsert/insert 함수가 이미 있을 수 있음.
    # 여기서는 "best-effort"로 insert 시도.
    try:
        db.insert_report_artifact(
            cve_id=cve_id,
            alert_type=alert_type,
            notify_reason=notify_reason,
            object_path=report_path,
            kind="report_md",
            sha256=report_sha,
            bytes_len=len(report_bytes),
        )
        if rules_zip_path and rules_zip_bytes:
            db.insert_report_artifact(
                cve_id=cve_id,
                alert_type=alert_type,
                notify_reason=notify_reason,
                object_path=rules_zip_path,
                kind="rules_zip",
                sha256=rules_sha,
                bytes_len=len(rules_zip_bytes),
            )
    except Exception:
        # 메타 저장 실패해도 핵심 기능은 유지(링크 전달)
        pass

    return report_link, report_path, rules_zip_path, report_sha, (rules_sha or ""), content_hash
