import os
import sys
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.abspath(os.path.join(_THIS_DIR, ".."))
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

import argparse
import datetime as dt
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Tuple

from blacklist_ip.config import load_settings
from blacklist_ip.collector_tier1 import collect_tier1_safe
from blacklist_ip.delta import compute_delta
from blacklist_ip.enricher_tier2 import Enricher
from blacklist_ip.scoring import apply_scoring
from blacklist_ip.blacklist_ip_notifier import build_slack_blocks, send_slack
from blacklist_ip.store_supabase import Store


def kst_today(tz_name: str) -> dt.date:
    tz = ZoneInfo(tz_name)
    return dt.datetime.now(tz).date()


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="daily", choices=["daily"])
    p.add_argument("--tz", default="Asia/Seoul")
    return p.parse_args()


def prioritize_new_ips(new_ips: List[str], tier1_records: Dict[str, Any]) -> List[str]:
    """
    Free-tier 방어용 우선순위:
      - base_score desc
      - sources_count desc
    """
    rows: List[Tuple[int, int, str]] = []
    for ip in new_ips:
        rec = tier1_records.get(ip)
        if not rec:
            continue
        base = int(getattr(rec, "base_score", 0))
        scnt = len(getattr(rec, "sources", []) or [])
        rows.append((base, scnt, ip))
    rows.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [x[2] for x in rows]


def main():
    pipeline_start = time.time()
    args = parse_args()
    settings = load_settings()

    report_date = kst_today(args.tz)
    yesterday = report_date - dt.timedelta(days=1)
    print(f"=== The Shield Daily Pipeline ({report_date.isoformat()}) ===", flush=True)

    store = Store(settings.supabase_url, settings.supabase_key)

    # -------------------------
    # Tier 1: 전체 수집 (피드별 실패 허용)
    # -------------------------
    t0 = time.time()
    print("[Step 1/5] Tier 1: 피드 수집 중...", flush=True)
    tier1_records, feed_failures = collect_tier1_safe(settings.feeds_path)
    today_set = set(tier1_records.keys())
    print(f"  수집 완료: {len(tier1_records)}개 indicator ({time.time()-t0:.1f}s)", flush=True)
    if feed_failures:
        print(f"  피드 실패: {len(feed_failures)}건", flush=True)

    # -------------------------
    # Delta: 어제 대비 신규/제거
    # -------------------------
    t0 = time.time()
    print("[Step 2/5] Delta 계산 중...", flush=True)
    y_set = store.get_snapshot_indicator_set(yesterday)
    delta = compute_delta(y_set, today_set)
    print(f"  어제: {len(y_set)}개, 오늘: {len(today_set)}개", flush=True)
    print(f"  신규: {len(delta.new_indicators)}개, 제거: {len(delta.removed_indicators)}개 ({time.time()-t0:.1f}s)", flush=True)

    # 어제의 고위험 IP 중 방화벽 제거/검토 대상 식별
    removed_set = set(delta.removed_indicators)
    yesterday_highrisk = store.get_highrisk_indicators(yesterday)

    # Case 1: 어제 Critical/High → 오늘 피드에서 완전 사라짐
    removed_highrisk = [
        r for r in yesterday_highrisk
        if r.get("indicator") in removed_set
    ]
    # Case 2: 어제 Critical/High → 오늘 피드에 있지만 Medium/Low로 등급 하락
    # (scoring 완료 후 아래에서 계산 - scored 결과 필요)

    # -------------------------
    # Tier 2: 신규 IP만 enrichment (CIDR 제외)
    # -------------------------
    t0 = time.time()
    print("[Step 3/5] Tier 2: Enrichment 시작...", flush=True)
    new_ips = [x for x in delta.new_indicators if "/" not in x]
    prioritized_new_ips = prioritize_new_ips(new_ips, tier1_records)
    print(f"  신규 IP (CIDR 제외): {len(new_ips)}개, 우선순위 정렬 완료", flush=True)

    enricher = Enricher(
        abuseipdb_key=settings.abuseipdb_api_key,
        store=store,
        quotas=settings.quotas,
        cache_ttl_hours=settings.cache_ttl_hours,
        timeouts=settings.timeouts,
        ratelimit=settings.ratelimit,
        max_enrich=settings.max_enrich_count,
        workers=settings.enrich_workers,
    )

    enrichment = enricher.enrich_many(prioritized_new_ips)
    print(f"  Enrichment 완료 ({time.time()-t0:.1f}s)", flush=True)

    # -------------------------
    # Scoring (기간 기반 가중치 + 카테고리별 임계값)
    # -------------------------
    t0 = time.time()
    print("[Step 4/5] Scoring 중...", flush=True)

    # 기간 기반 가중치: 기존 IP의 연속 등장 일수 조회
    existing_ips = [ip for ip in today_set if ip not in set(delta.new_indicators)]
    streak_data = {}
    if existing_ips:
        # 기존 IP 중 상위 500개만 조회 (API 부하 방어)
        sample = sorted(existing_ips)[:500]
        try:
            streak_data = store.get_indicator_streak(sample, report_date, lookback_days=7)
            if streak_data:
                print(f"  기간 가중치: {len(streak_data)}개 IP에 적용 (최대 streak: {max(streak_data.values())}일)", flush=True)
        except Exception as e:
            print(f"  [!] 기간 가중치 조회 실패 (무시): {e}", flush=True)

    scored = apply_scoring(
        tier1_records=tier1_records,
        enrichment=enrichment,
        critical=settings.critical_threshold,
        high=settings.high_threshold,
        medium=settings.medium_threshold,
        enable_source_bonus=settings.enable_source_bonus,
        source_bonus_step=settings.source_bonus_step,
        source_bonus_cap=settings.source_bonus_cap,
        streak_data=streak_data,
    )
    print(f"  Scoring 완료: {len(scored)}개 ({time.time()-t0:.1f}s)", flush=True)

    # Case 2 계산: 어제 Critical/High → 오늘 Medium/Low로 등급 하락
    degraded_highrisk = []
    for r in yesterday_highrisk:
        ip = r.get("indicator")
        if ip in removed_set:
            continue  # Case 1에 해당 (이미 removed_highrisk에 포함)
        today_record = scored.get(ip)
        if today_record and today_record.get("risk") in ("Medium", "Low"):
            degraded_highrisk.append({
                "indicator": ip,
                "yesterday_score": r.get("final_score", 0),
                "yesterday_risk": r.get("risk", "-"),
                "today_score": today_record.get("final_score", 0),
                "today_risk": today_record.get("risk", "-"),
                "category": r.get("category", "-"),
            })
    degraded_highrisk.sort(key=lambda x: x["yesterday_score"], reverse=True)

    if removed_highrisk:
        print(f"  방화벽 제거 대상: {len(removed_highrisk)}개 (어제 고위험 → 오늘 피드에서 제거됨)", flush=True)
    if degraded_highrisk:
        print(f"  등급 하락 검토: {len(degraded_highrisk)}개 (어제 고위험 → 오늘 Medium/Low)", flush=True)

    api_usage = {
        "abuseipdb": enricher.usage.abuseipdb,
        "internetdb": enricher.usage.internetdb,
    }

    # -------------------------
    # Persist snapshot
    # -------------------------
    t0 = time.time()
    print("[Step 5/5] Supabase 저장 + Slack 전송 중...", flush=True)
    store.upsert_snapshot(
        date=report_date,
        scored=scored,
        new_count=len(delta.new_indicators),
        removed_count=len(delta.removed_indicators),
        api_usage=api_usage,
    )
    print(f"  Supabase 저장 완료 ({time.time()-t0:.1f}s)", flush=True)

    # -------------------------
    # Slack report
    # -------------------------
    blocks = build_slack_blocks(
        report_date_kst=report_date,
        scored=scored,
        new_indicators=delta.new_indicators,
        removed_indicators=delta.removed_indicators,
        topn=settings.topn_report,
        api_usage=api_usage,
        feed_failures=feed_failures,
        removed_highrisk=removed_highrisk,
        degraded_highrisk=degraded_highrisk,
    )
    send_slack(settings.slack_webhook_url, blocks)
    print(f"  Slack 전송 완료", flush=True)

    elapsed = time.time() - pipeline_start
    print(f"\n=== Pipeline 완료 (총 {elapsed:.1f}s / {elapsed/60:.1f}min) ===", flush=True)


if __name__ == "__main__":
    main()