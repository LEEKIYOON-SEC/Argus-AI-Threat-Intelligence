from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import List, Tuple

from .logging_utils import setup_logging, get_logger
from .config import load_config
from .supabase_db import SupabaseDB
from .slack import post_slack

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

log = get_logger("argus.main")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _summarize_official_hits(official_hits: list[dict]) -> List[str]:
    lines: List[str] = []
    if not official_hits:
        return ["- (none)"]
    # 너무 길어지지 않게 요약(근거는 report rules section에 상세)
    for h in official_hits[:60]:
        lines.append(f"- [{h.get('engine')}] {h.get('source')} :: {h.get('rule_path')} (ref {h.get('reference')})")
    if len(official_hits) > 60:
        lines.append(f"- ...(total {len(official_hits)} hits)")
    return lines


def _build_ai_rules_section_md(ai_rules) -> str:
    lines: List[str] = []
    lines.append("## 8) Rules (AI-generated)")
    if not ai_rules:
        lines.append("- No AI-generated rules in this run.")
        return "\n".join(lines).strip() + "\n"

    # 검증 PASS만 번들에 들어가지만, FAIL도 감사용으로 기록
    pass_cnt = sum(1 for r in ai_rules if r.validated)
    fail_cnt = sum(1 for r in ai_rules if not r.validated)
    lines.append(f"- Generated: {len(ai_rules)} (validated PASS={pass_cnt}, FAIL={fail_cnt})")
    lines.append("")

    lines.append("### 8.1 Validation summary")
    for r in ai_rules:
        status = "PASS" if r.validated else "FAIL"
        lines.append(f"- {status} [{r.engine}] fp {r.fingerprint[:12]} conf={r.confidence} notes={r.notes[:120]}")
    lines.append("")

    # 실패 details는 상위 일부만
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


def main() -> None:
    setup_logging()
    cfg = load_config()
    db = SupabaseDB(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)

    selftest = os.getenv("ARGUS_SELFTEST", "").strip().lower() in ("1", "true", "yes", "y", "on")
    run_ok = False

    try:
        since = db.get_last_poll_time(default_minutes=60)
        now = _utcnow()

        if selftest:
            post_slack(cfg.SLACK_WEBHOOK_URL, "🧪 Argus 셀프테스트: CVE→KEV/EPSS→룰(공식/AI)→검증→Report/Slack")

        # 1) CVE.org PUBLISHED 신규 수집
        cves = fetch_cveorg_published_since(since, until=now)
        if not cves:
            db.log_run("RUN", True, f"no new CVE PUBLISHED since {since.isoformat()}")
            run_ok = True
            return

        # 2) KEV/EPSS enrich
        cves = enrich_with_kev_epss(cfg, cves)

        sent = 0
        for cve in cves:
            cve_id = cve["cve_id"]

            # 2-1) 파생 위험 플래그 계산
            _ = compute_risk_flags(cfg, cve)

            prev = db.get_cve_state(cve_id)

            # dedup 안정화(현재 DB에 references 저장 안함 → 매번 UPDATE 방지)
            prev_cmp = None
            if prev:
                prev_cmp = dict(prev)
                prev_cmp["references"] = cve.get("references") or []

            # 3) 기본 notify 판정(정책 + 변화)
            notify, reason = should_notify(cfg, cve, prev_cmp)
            change_kind = classify_change(prev_cmp, cve) if prev_cmp else "NO_PREV"

            # 4) "AI → 공식 룰 발견" 갱신 재알림 강제 조건을 만들기 위해
            #    먼저 공식 룰을 수집/검증해 '공식 룰 존재'를 판단한다.
            official_hits = fetch_official_rules(cfg, cve_id)
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
                # 이전에 AI_ONLY였거나, 공식 fp가 변했는데 기존에 공식이 없던 케이스면 갱신 재알림
                if prev_rule_status in ("AI_ONLY", "NONE") and official_fp and official_fp != prev_official_fp:
                    forced_rule_update = True

            # notify가 아니지만, 공식 룰 발견 갱신이면 강제 notify
            if (not notify) and forced_rule_update:
                notify = True
                reason = "공식/공개 룰 발견으로 갱신 재알림"
                change_kind = "UPDATE"

            # 알림 대상이 아니어도 상태 업데이트는 수행
            if not notify:
                db.upsert_cve_state(cve, last_seen_at=_utcnow())
                continue

            # alert_type 결정
            if not prev:
                alert_type = "NEW_CVE_PUBLISHED"
            elif forced_rule_update or change_kind == "ESCALATION":
                alert_type = "UPDATE_ESCALATION"
            else:
                alert_type = "HIGH_RISK"

            # 5) 패치/권고 텍스트(best-effort, 가능한 경우 무조건)
            patch_findings = fetch_patch_findings_from_references(cve.get("references") or [], max_pages=4)
            patch_section_md = build_patch_section_md(patch_findings)

            # 6) Evidence Bundle 구성(LLM에 URL 대신 텍스트 근거 제공)
            official_summary_lines = _summarize_official_hits(official_hits)
            evidence_text = build_evidence_bundle_text(
                cfg=cfg,
                cve=cve,
                patch_findings=patch_findings,
                official_rules_summary_lines=official_summary_lines,
                ai_rule_generation_notes=None,
            )

            # 7) AI 룰 생성(공식 룰이 없거나, 정책 라우팅상 필요 엔진이 비어있는 경우)
            #    - sigma는 무조건 생성 정책이지만,
            #      공식 Sigma 룰이 있으면 AI 생성은 생략 가능.
            #    - 다만 기업 운영 관점에서 "공식 sigma 없음"이면 AI sigma를 생성해 채움.
            has_sigma_official = any(a.validated and a.engine == "sigma" for a in official_pass)
            need_ai = (not had_official_now) or (not has_sigma_official)

            ai_rules = []
            if need_ai:
                ai_rules = generate_ai_rules(cfg=cfg, cve=cve, evidence_bundle_text=evidence_text, prefer_snort3=False)

            # 8) rules.zip 만들기: 공식 PASS + AI PASS 전부 포함
            zip_files: List[Tuple[str, bytes]] = []
            for a in official_pass:
                # validate_and_build_bundle에서 path 정규화와 동일 규칙 사용
                zpath = f"rules/{a.engine}/{a.source}/{a.rule_path}".replace("..", "_")
                zip_files.append((zpath, (a.rule_text.strip() + "\n").encode("utf-8")))

            ai_pass = [r for r in ai_rules if r.validated]
            for r in ai_pass:
                zpath = f"rules/{r.engine}/AI/generated_{cve_id}_{r.fingerprint[:12]}.txt"
                zip_files.append((zpath, (r.rule_text.strip() + "\n").encode("utf-8")))

            rules_zip_bytes = write_zip(zip_files) if zip_files else None

            # rule status 결정(운영/갱신 트리거용)
            if official_pass and ai_pass:
                rule_status = "OFFICIAL_AND_AI"
            elif official_pass and (not ai_pass):
                # 이전에 AI_ONLY였다가 official이 생긴 케이스면 OFFICIAL_AFTER_AI로 명시
                rule_status = "OFFICIAL_AFTER_AI" if prev_rule_status == "AI_ONLY" else "OFFICIAL_ONLY"
            elif (not official_pass) and ai_pass:
                rule_status = "AI_ONLY"
            else:
                rule_status = "NONE"

            # 공식/AI 룰 지문
            official_bundle_fp = official_fp
            ai_bundle_fp = sha256_hex(("\n".join(sorted([r.fingerprint for r in ai_pass]))).encode("utf-8")) if ai_pass else ""

            ai_rules_section_md = _build_ai_rules_section_md(ai_rules)

            # 9) Report 생성(룰 섹션+AI 섹션+패치 섹션 포함) → Storage 저장(+rules.zip)
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

            # 10) Slack: 검증 PASS 룰 일부만 복붙 블록으로 포함(상위 3개)
            pass_rules_for_slack = []
            for a in official_pass:
                pass_rules_for_slack.append(
                    {"engine": a.engine, "source": a.source, "rule_path": a.rule_path, "rule_text": a.rule_text}
                )
            for r in ai_pass:
                pass_rules_for_slack.append(
                    {
                        "engine": r.engine,
                        "source": "AI",
                        "rule_path": f"generated_{r.fingerprint[:12]}",
                        "rule_text": r.rule_text,
                    }
                )

            slack_text = format_slack_message(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
                report_link=report_link,
                top_validated_rules=pass_rules_for_slack,
                include_rule_blocks_max=3,
            )
            post_slack(cfg.SLACK_WEBHOOK_URL, slack_text)

            # 11) payload hash + state 업데이트
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
                "official_rules_fp": official_bundle_fp,
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
                last_official_rule_fingerprint=official_bundle_fp or None,
                last_ai_rule_fingerprint=ai_bundle_fp or None,
            )

            sent += 1

        db.log_run("RUN", True, f"processed={len(cves)} sent={sent} since={since.isoformat()}")
        run_ok = True

    except Exception as e:
        db.log_run("RUN", False, f"run failed: {e}")
        raise

    finally:
        if run_ok:
            log.info("Run OK")
        else:
            log.error("Run FAILED")


if __name__ == "__main__":
    main()
