from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Tuple

from .logging_utils import setup_logging, get_logger
from .config import load_config
from .supabase_db import SupabaseDB
from .slack import post_slack

from .runtime_overrides import apply_runtime_overrides

from .cve_sources import fetch_cveorg_published_since
from .kev_epss import enrich_with_kev_epss
from .dedup import should_notify, classify_change, compute_payload_hash
from .scoring import compute_risk_flags

from .slack_format import format_slack_message
from .report_store import build_report_markdown, store_report_and_get_link

from .rules_official import fetch_official_rules
from .rules_bundle import validate_and_build_bundle
from .util.ziputil import write_zip
from .util.textutil import sha256_hex

from .patch_intel import fetch_patch_findings_from_references, build_patch_section_md
from .evidence_bundle import build_evidence_bundle_text
from .ai_rules import generate_ai_rules

from .vulncheck_intel import fetch_vulncheck_findings
from .github_osint import (
    search_repos_by_cve,
    search_code_by_cve,
    enrich_code_findings_with_snippets,
)
from .github_rule_candidates import fetch_trusted_github_rule_candidates

log = get_logger("argus.main")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _summarize_official_hits(official_hits: list[dict]) -> List[str]:
    if not official_hits:
        return ["- (none)"]
    lines: List[str] = []
    for h in official_hits[:80]:
        lines.append(f"- [{h.get('engine')}] {h.get('source')} :: {h.get('rule_path')} (ref {h.get('reference')})")
    if len(official_hits) > 80:
        lines.append(f"- ...(total {len(official_hits)} hits)")
    return lines


def _build_ai_rules_section_md(ai_rules) -> str:
    lines: List[str] = []
    lines.append("## 8) Rules (AI-generated)")
    if not ai_rules:
        lines.append("- No AI-generated rules in this run.")
        return "\n".join(lines).strip() + "\n"

    pass_cnt = sum(1 for r in ai_rules if r.validated)
    fail_cnt = sum(1 for r in ai_rules if not r.validated)
    lines.append(f"- Generated: {len(ai_rules)} (validated PASS={pass_cnt}, FAIL={fail_cnt})")
    lines.append("")

    lines.append("### 8.1 Validation summary")
    for r in ai_rules:
        status = "PASS" if r.validated else "FAIL"
        lines.append(f"- {status} [{r.engine}] fp {r.fingerprint[:12]} conf={r.confidence} notes={r.notes[:120]}")
    lines.append("")

    fails = [r for r in ai_rules if not r.validated]
    if fails:
        lines.append("### 8.2 Failure details (first 800 chars each)")
        for r in fails[:5]:
            det = (r.validation_details or "").strip()
            if len(det) > 800:
                det = det[:800] + "…(truncated)"
            lines.append(f"- [{r.engine}] fp {r.fingerprint[:12]}")
            lines.append("```")
            lines.append(det)
            lines.append("```")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _rules_zip_readme(cve_id: str) -> str:
    return f"""# Argus-AI-Threat Intelligence - Rules Bundle

CVE: {cve_id}

## Folder layout
- rules/suricata/<source>/...
- rules/snort2/<source>/...
- rules/snort3/<source>/...
- rules/sigma/<source>/...
- rules/yara/<source>/...
- rules/<engine>/AI/... (AI-generated, validated PASS only)

## Notes
- Only rules that PASS engine validation are included in this ZIP.
- Full Evidence Bundle (LLM input basis) is in the Report link delivered to Slack.
"""


def _get_int_env(name: str, default: int) -> int:
    try:
        v = int(os.getenv(name, str(default)).strip())
        return max(0, v)
    except Exception:
        return default


def main() -> None:
    setup_logging()

    cfg = load_config()

    # ✅ DB settings를 런타임에 cfg로 주입 (웹 UI 변경이 즉시 반영되는 핵심)
    apply_runtime_overrides(cfg)

    db = SupabaseDB(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)

    selftest = os.getenv("ARGUS_SELFTEST", "").strip().lower() in ("1", "true", "yes", "y", "on")
    run_ok = False

    # 운영 파라미터: cfg 우선, 없으면 env 기본
    gh_snippet_max = getattr(cfg, "ARGUS_GH_SNIPPET_FETCH_MAX", None)
    if gh_snippet_max is None:
        gh_snippet_max = _get_int_env("ARGUS_GH_SNIPPET_FETCH_MAX", 2)

    gh_rule_candidates_max = getattr(cfg, "ARGUS_GH_RULE_CANDIDATES_MAX", None)
    if gh_rule_candidates_max is None:
        gh_rule_candidates_max = _get_int_env("ARGUS_GH_RULE_CANDIDATES_MAX", 4)

    slack_rule_blocks_max = getattr(cfg, "ARGUS_SLACK_RULE_BLOCKS_MAX", None)
    if slack_rule_blocks_max is None:
        slack_rule_blocks_max = _get_int_env("ARGUS_SLACK_RULE_BLOCKS_MAX", 3)

    try:
        since = db.get_last_poll_time(default_minutes=60)
        now = _utcnow()

        if selftest:
            post_slack(
                cfg.SLACK_WEBHOOK_URL,
                f"🧪 Argus 셀프테스트: GH_snippet_max={gh_snippet_max}, GH_rule_candidates_max={gh_rule_candidates_max}, slack_rule_blocks_max={slack_rule_blocks_max}, EPSS_IMM={getattr(cfg,'EPSS_IMMEDIATE',None)}, EPSS_COND={getattr(cfg,'EPSS_CONDITIONAL',None)}",
            )

        cves = fetch_cveorg_published_since(since, until=now)
        if not cves:
            db.log_run("RUN", True, f"no new CVE PUBLISHED since {since.isoformat()}")
            run_ok = True
            return

        cves = enrich_with_kev_epss(cfg, cves)

        sent = 0
        for cve in cves:
            cve_id = cve["cve_id"]
            _ = compute_risk_flags(cfg, cve)

            prev = db.get_cve_state(cve_id)
            prev_cmp = None
            if prev:
                prev_cmp = dict(prev)
                prev_cmp["references"] = cve.get("references") or []

            notify, reason = should_notify(cfg, cve, prev_cmp)
            change_kind = classify_change(prev_cmp, cve) if prev_cmp else "NO_PREV"

            vulncheck_findings = fetch_vulncheck_findings(cfg, cve_id)

            github_findings = []
            github_findings.extend(search_repos_by_cve(cfg, cve_id, max_items=4))
            github_findings.extend(search_code_by_cve(cfg, cve_id, max_items=8))
            github_findings = enrich_code_findings_with_snippets(
                cfg, github_findings, max_fetch=int(gh_snippet_max), snippet_max_chars=3500
            )

            github_rule_hits = fetch_trusted_github_rule_candidates(
                cfg, cve_id=cve_id, github_findings=github_findings, max_rules=int(gh_rule_candidates_max)
            )

            official_hits_base = fetch_official_rules(cfg, cve_id)
            official_hits = list(official_hits_base) + list(github_rule_hits)

            artifacts, _, official_fp, rules_section_md = validate_and_build_bundle(
                cfg=cfg,
                cve=cve,
                official_hits=official_hits,
            )
            official_pass = [a for a in artifacts if a.validated]
            had_official_now = bool(official_pass)

            prev_rule_status = (prev.get("last_rule_status") if prev else None) or "NONE"
            prev_official_fp = (prev.get("last_official_rule_fingerprint") if prev else None) or ""

            forced_rule_update = False
            if had_official_now:
                if prev_rule_status in ("AI_ONLY", "NONE"):
                    forced_rule_update = True
                elif official_fp and prev_official_fp and official_fp != prev_official_fp:
                    forced_rule_update = True
                elif official_fp and (not prev_official_fp):
                    forced_rule_update = True

            if (not notify) and forced_rule_update:
                notify = True
                reason = "공식/공개 룰 변경(추가/갱신)으로 재알림"
                change_kind = "UPDATE"

            if not notify:
                db.upsert_cve_state(cve, last_seen_at=_utcnow())
                continue

            if not prev:
                alert_type = "NEW_CVE_PUBLISHED"
            elif forced_rule_update or change_kind == "ESCALATION":
                alert_type = "UPDATE_ESCALATION"
            else:
                alert_type = "HIGH_RISK"

            patch_findings = fetch_patch_findings_from_references(cve.get("references") or [], max_pages=4)
            patch_section_md = build_patch_section_md(patch_findings)

            official_summary_lines = _summarize_official_hits(official_hits)
            evidence_text = build_evidence_bundle_text(
                cfg=cfg,
                cve=cve,
                patch_findings=patch_findings,
                official_rules_summary_lines=official_summary_lines,
                vulncheck_findings=vulncheck_findings,
                github_findings=github_findings,
                ai_rule_generation_notes=None,
            )

            has_sigma_official = any(a.validated and a.engine == "sigma" for a in official_pass)
            need_ai = (not had_official_now) or (not has_sigma_official)

            ai_rules = []
            if need_ai:
                ai_rules = generate_ai_rules(cfg=cfg, cve=cve, evidence_bundle_text=evidence_text, prefer_snort3=False)

            zip_files: List[Tuple[str, bytes]] = []
            zip_files.append(("README.md", _rules_zip_readme(cve_id).encode("utf-8")))

            for a in official_pass:
                zpath = f"rules/{a.engine}/{a.source}/{a.rule_path}".replace("..", "_")
                zip_files.append((zpath, (a.rule_text.strip() + "\n").encode("utf-8")))

            ai_pass = [r for r in ai_rules if r.validated]
            for r in ai_pass:
                zpath = f"rules/{r.engine}/AI/generated_{cve_id}_{r.fingerprint[:12]}.txt"
                zip_files.append((zpath, (r.rule_text.strip() + "\n").encode("utf-8")))

            rules_zip_bytes = write_zip(zip_files) if zip_files else None

            if official_pass and ai_pass:
                rule_status = "OFFICIAL_AND_AI"
            elif official_pass and (not ai_pass):
                rule_status = "OFFICIAL_AFTER_AI" if prev_rule_status == "AI_ONLY" else "OFFICIAL_ONLY"
            elif (not official_pass) and ai_pass:
                rule_status = "AI_ONLY"
            else:
                rule_status = "NONE"

            ai_bundle_fp = sha256_hex(("\n".join(sorted([r.fingerprint for r in ai_pass]))).encode("utf-8")) if ai_pass else ""
            ai_rules_section_md = _build_ai_rules_section_md(ai_rules)

            report_md = build_report_markdown(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
                evidence_bundle_text=evidence_text,
                rules_section_md=rules_section_md,
                ai_rules_section_md=ai_rules_section_md,
                patch_section_md=patch_section_md,
            )

            report_link, report_path, rules_zip_path, report_sha, rules_sha, content_hash = store_report_and_get_link(
                cfg,
                db,
                cve_id=cve_id,
                alert_type=alert_type,
                notify_reason=reason,
                report_md=report_md,
                kev_listed=bool(cve.get("is_cisa_kev") or False),
                rules_zip_bytes=rules_zip_bytes,
            )

            pass_rules_for_slack = []
            for a in official_pass:
                pass_rules_for_slack.append({"engine": a.engine, "source": a.source, "rule_path": a.rule_path, "rule_text": a.rule_text})
            for r in ai_pass:
                pass_rules_for_slack.append({"engine": r.engine, "source": "AI", "rule_path": f"generated_{r.fingerprint[:12]}", "rule_text": r.rule_text})

            slack_text = format_slack_message(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
                report_link=report_link,
                top_validated_rules=pass_rules_for_slack,
                include_rule_blocks_max=int(slack_rule_blocks_max),
                rules_zip_present=bool(rules_zip_path),
            )
            post_slack(cfg.SLACK_WEBHOOK_URL, slack_text)

            payload = {
                "cve_id": cve_id,
                "alert_type": alert_type,
                "reason": reason,
                "cvss_score": cve.get("cvss_score"),
                "cvss_vector": cve.get("cvss_vector"),
                "epss_score": cve.get("epss_score"),
                "is_cisa_kev": bool(cve.get("is_cisa_kev") or False),
                "attack_vector": cve.get("attack_vector"),
                "rule_status": rule_status,
                "official_rules_fp": official_fp,
                "ai_rules_fp": ai_bundle_fp,
                "has_rules_zip": bool(rules_zip_path),
                "content_hash": content_hash,
            }
            payload_hash = compute_payload_hash(payload)

            db.upsert_cve_state(
                cve,
                last_seen_at=_utcnow(),
                last_notified_at=_utcnow(),
                last_notified_type=alert_type,
                last_notify_reason=reason,
                last_payload_hash=payload_hash,
                last_report_path=report_path or None,
                last_rules_zip_path=rules_zip_path or None,
                last_rule_status=rule_status,
                last_official_rule_fingerprint=official_fp or None,
                last_ai_rule_fingerprint=ai_bundle_fp or None,
            )

            sent += 1

        db.log_run("RUN", True, f"processed={len(cves)} sent={sent} since={since.isoformat()}")
        run_ok = True

    except Exception as e:
        db.log_run("RUN", False, f"run failed: {e}")
        raise

    finally:
        log.info("Run %s", "OK" if run_ok else "FAILED")


if __name__ == "__main__":
    main()
