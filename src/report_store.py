from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from .util.textutil import sha256_hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts_for_path(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_report_markdown(
    *,
    cve: dict,
    alert_type: str,
    notify_reason: str,
    change_kind: str,
    evidence_bundle_text: str,
    rules_section_md: str | None = None,
    ai_rules_section_md: str | None = None,
    patch_section_md: str | None = None,
) -> str:
    """
    Report는 Slack 길이 제한/피로도를 줄이기 위한 '진실의 원본' 역할.
    - Evidence Bundle을 고정 섹션으로 포함(LLM 웹검색 불가 전제 보장)
    - 공식/AI 룰 섹션을 포함
    - 패치/권고 텍스트를 포함(가능하면 무조건)
    """
    cve_id = cve["cve_id"]

    lines: list[str] = []
    lines.append("# Argus-AI-Threat Intelligence Report")
    lines.append("")
    lines.append("## 1) Summary")
    lines.append(f"- CVE: {cve_id}")
    lines.append(f"- Alert Type: {alert_type}")
    lines.append(f"- Trigger: {notify_reason}")
    lines.append(f"- Change Kind: {change_kind}")
    lines.append(f"- Published: {cve.get('date_published')}")
    lines.append(f"- Updated: {cve.get('date_updated')}")
    lines.append("")

    lines.append("## 2) Technical Details (Raw)")
    lines.append(f"- CVSS Score: {cve.get('cvss_score')}")
    lines.append(f"- CVSS Severity: {cve.get('cvss_severity')}")
    lines.append(f"- CVSS Vector: {cve.get('cvss_vector')}")
    lines.append(f"- Attack Vector: {cve.get('attack_vector')}")
    lines.append(f"- CWE: {', '.join(cve.get('cwe_ids') or [])}")
    lines.append(f"- EPSS: {cve.get('epss_score')} (percentile {cve.get('epss_percentile')})")
    lines.append(f"- CISA KEV: {bool(cve.get('is_cisa_kev') or False)} (added {cve.get('kev_added_date')})")
    lines.append("")

    lines.append("## 3) Description (EN)")
    lines.append(cve.get("description_en") or "")
    lines.append("")

    lines.append("## 4) References")
    for r in (cve.get("references") or []):
        lines.append(f"- {r}")
    lines.append("")

    # Evidence Bundle: LLM 입력 근거의 재현성 핵심
    lines.append("## 5) Evidence Bundle (Normalized Text)")
    lines.append("```")
    lines.append((evidence_bundle_text or "").rstrip())
    lines.append("```")
    lines.append("")

    if rules_section_md:
        lines.append(rules_section_md.strip())
        lines.append("")

    if ai_rules_section_md:
        lines.append(ai_rules_section_md.strip())
        lines.append("")

    if patch_section_md:
        lines.append(patch_section_md.strip())
        lines.append("")

    return "\n".join(lines).strip() + "\n"


def store_report_and_get_link(
    cfg,
    db,
    *,
    cve_id: str,
    alert_type: str,
    notify_reason: str,
    report_md: str,
    kev_listed: bool,
    rules_zip_bytes: Optional[bytes] = None,
) -> Tuple[str, str, Optional[str], str, Optional[str], str]:
    """
    Storage에 report.md (+ optional rules.zip) 저장 + Signed URL 생성.
    """
    if not cfg.USE_STORAGE:
        return "Storage disabled", "", None, "", None, ""

    now = _utcnow()
    ts = _ts_for_path(now)
    bucket = cfg.STORAGE_BUCKET

    report_path = f"reports/{cve_id}/{ts}.md"
    rules_zip_path = f"rules/{cve_id}/{ts}.zip" if rules_zip_bytes else None

    report_bytes = report_md.encode("utf-8")
    report_sha = sha256_hex(report_bytes)
    rules_sha = sha256_hex(rules_zip_bytes) if rules_zip_bytes else None
    content_hash = sha256_hex((report_sha + (rules_sha or "")).encode("utf-8"))

    storage = db.sb.storage.from_(bucket)
    storage.upload(
        report_path,
        report_bytes,
        file_options={"content-type": "text/markdown; charset=utf-8", "upsert": "true"},
    )

    if rules_zip_bytes and rules_zip_path:
        storage.upload(
            rules_zip_path,
            rules_zip_bytes,
            file_options={"content-type": "application/zip", "upsert": "true"},
        )

    expiry_seconds = int(cfg.REPORT_TTL_DAYS) * 24 * 3600
    signed = storage.create_signed_url(report_path, expiry_seconds)
    report_link = signed.get("signedURL") or signed.get("signedUrl") or str(signed)

    retention_until = now + timedelta(days=int(cfg.REPORT_TTL_DAYS))

    db.insert_report_object(
        cve_id=cve_id,
        alert_type=alert_type,
        primary_reason=notify_reason,
        report_path=report_path,
        rules_zip_path=rules_zip_path,
        content_hash=content_hash,
        report_sha256=report_sha,
        rules_sha256=rules_sha,
        retention_until=retention_until,
        kev_listed=bool(kev_listed),
        signed_url_expiry_seconds=expiry_seconds,
    )

    return report_link, report_path, rules_zip_path, report_sha, rules_sha, content_hash
