from __future__ import annotations

import os
from datetime import datetime, timezone

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

log = get_logger("argus.main")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def main() -> None:
    setup_logging()
    cfg = load_config()
    db = SupabaseDB(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)

    # 스팸 방지: 기본 OFF (운영에서는 false 유지)
    selftest = os.getenv("ARGUS_SELFTEST", "").strip().lower() in ("1", "true", "yes", "y", "on")

    run_ok = False
    try:
        since = db.get_last_poll_time(default_minutes=60)
        now = _utcnow()

        if selftest:
            post_slack(cfg.SLACK_WEBHOOK_URL, "🧪 Argus 셀프테스트: CVE 수집/정책/룰 검증 파이프라인 시작")

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

            # 파생 위험 플래그 계산(내부 dict에 기록)
            _ = compute_risk_flags(cfg, cve)

            prev = db.get_cve_state(cve_id)

            # dedup 안정화(현재 DB에 references 저장 안함 → 매번 UPDATE 방지)
            prev_cmp = None
            if prev:
                prev_cmp = dict(prev)
                prev_cmp["references"] = cve.get("references") or []

            notify, reason = should_notify(cfg, cve, prev_cmp)

            # DB에는 last_seen 업데이트는 항상 수행
            if not notify:
                db.upsert_cve_state(cve, last_seen_at=_utcnow())
                continue

            change_kind = classify_change(prev_cmp, cve)

            if not prev:
                alert_type = "NEW_CVE_PUBLISHED"
            elif change_kind == "ESCALATION":
                alert_type = "UPDATE_ESCALATION"
            else:
                alert_type = "HIGH_RISK"

            # 3) 공식/공개 룰 수집(전부) → 라우팅/검증 → 번들/리포트 섹션 생성
            official_hits = fetch_official_rules(cfg, cve_id)

            artifacts, rules_zip_bytes, official_fp, rules_section_md = validate_and_build_bundle(
                cfg=cfg,
                cve=cve,
                official_hits=official_hits,
            )

            # Slack에 포함할 “검증 PASS 룰(복붙 가능)” 상위 N개
            pass_rules = []
            for a in artifacts:
                if a.validated:
                    pass_rules.append(
                        {
                            "engine": a.engine,
                            "source": a.source,
                            "rule_path": a.rule_path,
                            "rule_text": a.rule_text,
                        }
                    )

            # 4) Report 생성(+룰 섹션 포함) / Storage 저장(+rules.zip 함께 저장) / 링크 생성
            report_md = build_report_markdown(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
                rules_section_md=rules_section_md,
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

            # 5) Slack 메시지 구성/발송(룰 복붙 블록 포함)
            slack_text = format_slack_message(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
                report_link=report_link,
                top_validated_rules=pass_rules,
                include_rule_blocks_max=3,  # 필요 시 정책화 가능
            )
            post_slack(cfg.SLACK_WEBHOOK_URL, slack_text)

            # 6) payload hash + state 업데이트
            payload = {
                "cve_id": cve_id,
                "alert_type": alert_type,
                "reason": reason,
                "cvss_score": cve.get("cvss_score"),
                "cvss_vector": cve.get("cvss_vector"),
                "epss_score": cve.get("epss_score"),
                "is_cisa_kev": bool(cve.get("is_cisa_kev") or False),
                "attack_vector": cve.get("attack_vector"),
                "official_rules_fp": official_fp,
                "has_rules_zip": bool(rules_zip_path),
            }
            payload_hash = compute_payload_hash(payload)

            # 룰 상태(현재는 공식/공개만 처리)
            if pass_rules:
                rule_status = "OFFICIAL_ONLY"
            else:
                rule_status = "NONE"

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
                last_official_rule_fingerprint=official_fp,
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
