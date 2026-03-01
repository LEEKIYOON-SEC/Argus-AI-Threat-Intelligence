"""
GitHub Pages 대시보드용 데이터 Export

Supabase에서 CVE/Shield 데이터를 조회하여
docs/data/*.json 정적 파일로 생성한다.
브라우저에서 직접 Supabase를 호출하지 않으므로 free tier 안전.
"""

import os
import sys
import json
import datetime as dt
from collections import defaultdict

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from supabase import create_client


def _get_client():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not url or not key:
        return None
    return create_client(url, key)


def export_cves(client, days: int = 90) -> list:
    """최근 N일 CVE 데이터 export (페이지네이션으로 전체 로드)"""
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()

    rows = []
    page_size = 1000
    offset = 0
    while True:
        response = client.table("cves") \
            .select("id, cvss_score, epss_score, is_kev, last_alert_at, last_alert_state, report_url, updated_at") \
            .gte("updated_at", cutoff) \
            .order("updated_at", desc=True) \
            .range(offset, offset + page_size - 1) \
            .execute()

        page = response.data or []
        if not page:
            break
        rows.extend(page)
        if len(page) < page_size:
            break
        offset += page_size

    result = []

    for row in rows:
        state = row.get("last_alert_state") or {}
        entry = {
            "id": row.get("id", ""),
            "title": state.get("title_ko") or state.get("title", "N/A"),
            "description": state.get("desc_ko") or state.get("description", "")[:300],
            "cvss": row.get("cvss_score", 0) or 0,
            "epss": row.get("epss_score", 0) or 0,
            "is_kev": row.get("is_kev", False),
            "cwe": state.get("cwe", []),
            "affected": [],
            "report_url": row.get("report_url"),
            "date": row.get("last_alert_at", row.get("updated_at", "")),
        }

        # affected 정보 간략화
        for aff in state.get("affected", [])[:3]:
            entry["affected"].append({
                "vendor": aff.get("vendor", "Unknown"),
                "product": aff.get("product", "Unknown"),
                "versions": aff.get("versions", ""),
            })

        # 심각도 등급 계산
        score = entry["cvss"]
        if score >= 9.0:
            entry["severity"] = "Critical"
        elif score >= 7.0:
            entry["severity"] = "High"
        elif score >= 4.0:
            entry["severity"] = "Medium"
        elif score > 0:
            entry["severity"] = "Low"
        else:
            entry["severity"] = "None"

        result.append(entry)

    return result


def export_blacklist(client, days: int = 7) -> dict:
    """최근 N일 Shield IP 데이터 export"""
    today = dt.date.today()

    # 최근 날짜의 스냅샷 조회
    snapshots = []
    for d in range(days):
        target_date = (today - dt.timedelta(days=d)).isoformat()
        res = client.table("shield_daily_snapshots") \
            .select("*") \
            .eq("date", target_date) \
            .execute()
        if res.data:
            snapshots.append(res.data[0])

    # 오늘(또는 가장 최근) 날짜의 indicator 데이터
    latest_date = today.isoformat()
    if snapshots:
        latest_date = snapshots[0].get("date", today.isoformat())

    # 전체 indicator 조회 (페이지네이션으로 전체 로드)
    indicators = []
    page_size = 1000
    offset = 0
    while True:
        indicators_res = client.table("shield_indicators") \
            .select("indicator, type, category, sources, base_score, final_score, risk, enrichment") \
            .eq("date", latest_date) \
            .order("final_score", desc=True) \
            .range(offset, offset + page_size - 1) \
            .execute()

        rows = indicators_res.data or []
        if not rows:
            break

        for row in rows:
            enrichment = row.get("enrichment") or {}
            abuse = enrichment.get("abuseipdb") or {}

            indicators.append({
                "indicator": row.get("indicator", ""),
                "type": row.get("type", "ip"),
                "category": row.get("category", "unknown"),
                "sources": row.get("sources", []),
                "score": row.get("final_score", 0),
                "risk": row.get("risk", "Low"),
                "abuse_confidence": abuse.get("abuseConfidenceScore"),
                "abuse_reports": abuse.get("totalReports"),
            })

        if len(rows) < page_size:
            break
        offset += page_size

    # 어제 → 오늘 사이 제거/등급 하락 IP (평판 회복 IP)
    yesterday = (today - dt.timedelta(days=1)).isoformat()
    recovered_ips = _get_recovered_ips(client, yesterday, latest_date)

    return {
        "date": latest_date,
        "snapshots": snapshots,
        "indicators": indicators,
        "recovered": recovered_ips,
    }


def _get_recovered_ips(client, yesterday_date: str, today_date: str) -> list:
    """어제 고위험이었으나 오늘 제거되거나 등급이 하락한 IP 목록"""
    try:
        # 어제 Critical/High IP 조회
        yesterday_res = client.table("shield_indicators") \
            .select("indicator, final_score, risk, category") \
            .eq("date", yesterday_date) \
            .in_("risk", ["Critical", "High"]) \
            .order("final_score", desc=True) \
            .limit(200) \
            .execute()

        yesterday_highrisk = {r["indicator"]: r for r in (yesterday_res.data or [])}
        if not yesterday_highrisk:
            return []

        # 오늘 데이터에서 해당 IP들 조회
        today_ips = list(yesterday_highrisk.keys())
        today_res = client.table("shield_indicators") \
            .select("indicator, final_score, risk") \
            .eq("date", today_date) \
            .in_("indicator", today_ips[:100]) \
            .execute()

        today_map = {r["indicator"]: r for r in (today_res.data or [])}

        recovered = []
        for ip, y_data in yesterday_highrisk.items():
            t_data = today_map.get(ip)
            if t_data is None:
                # 피드에서 완전 제거됨
                recovered.append({
                    "indicator": ip,
                    "yesterday_score": y_data.get("final_score", 0),
                    "yesterday_risk": y_data.get("risk", "-"),
                    "today_score": 0,
                    "today_risk": "Removed",
                    "category": y_data.get("category", "-"),
                    "status": "removed",
                })
            elif t_data.get("risk") in ("Medium", "Low"):
                # 등급 하락
                recovered.append({
                    "indicator": ip,
                    "yesterday_score": y_data.get("final_score", 0),
                    "yesterday_risk": y_data.get("risk", "-"),
                    "today_score": t_data.get("final_score", 0),
                    "today_risk": t_data.get("risk", "-"),
                    "category": y_data.get("category", "-"),
                    "status": "degraded",
                })

        recovered.sort(key=lambda x: x["yesterday_score"], reverse=True)
        return recovered

    except Exception as e:
        print(f"  [!] 평판 회복 IP 조회 실패: {e}", flush=True)
        return []


def export_stats(cve_data: list, blacklist_data: dict) -> dict:
    """통계 집계"""
    now = dt.datetime.now(dt.timezone.utc)

    # CVE 통계
    severity_counts = defaultdict(int)
    vendor_counts = defaultdict(int)
    daily_counts = defaultdict(int)
    recent_24h = 0
    kev_count = 0

    for cve in cve_data:
        severity_counts[cve.get("severity", "None")] += 1

        if cve.get("is_kev"):
            kev_count += 1

        # 일별 집계
        date_str = cve.get("date", "")
        if date_str:
            try:
                day = date_str[:10]
                daily_counts[day] += 1
                cve_dt = dt.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if (now - cve_dt).total_seconds() < 86400:
                    recent_24h += 1
            except (ValueError, TypeError):
                pass

        # 벤더별 집계
        for aff in cve.get("affected", []):
            vendor = aff.get("vendor", "Unknown")
            if vendor and vendor != "Unknown":
                vendor_counts[vendor] += 1

    # 일별 추이 (최근 30일, 정렬)
    daily_trend = sorted(daily_counts.items(), key=lambda x: x[0])[-30:]

    # 벤더 TOP 10
    vendor_top = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    # 블랙리스트 통계
    bl_risk_counts = defaultdict(int)
    bl_category_counts = defaultdict(int)
    for ind in blacklist_data.get("indicators", []):
        bl_risk_counts[ind.get("risk", "Low")] += 1
        bl_category_counts[ind.get("category", "unknown")] += 1

    bl_daily_trend = []
    for snap in reversed(blacklist_data.get("snapshots", [])):
        bl_daily_trend.append({
            "date": snap.get("date", ""),
            "total": snap.get("total_count", 0),
            "new": snap.get("new_count", 0),
            "removed": snap.get("removed_count", 0),
        })

    return {
        "generated_at": now.isoformat(),
        "cve": {
            "total": len(cve_data),
            "recent_24h": recent_24h,
            "kev_count": kev_count,
            "severity": dict(severity_counts),
            "daily_trend": [{"date": d, "count": c} for d, c in daily_trend],
            "top_vendors": [{"vendor": v, "count": c} for v, c in vendor_top],
        },
        "blacklist": {
            "total": len(blacklist_data.get("indicators", [])),
            "risk": dict(bl_risk_counts),
            "categories": dict(bl_category_counts),
            "daily_trend": bl_daily_trend,
            "recovered_count": len(blacklist_data.get("recovered", [])),
            "recovered_removed": len([r for r in blacklist_data.get("recovered", []) if r.get("status") == "removed"]),
            "recovered_degraded": len([r for r in blacklist_data.get("recovered", []) if r.get("status") == "degraded"]),
        },
    }


def _generate_sample_data(data_dir: str):
    """Supabase 자격증명 없을 때 빈 샘플 데이터 생성 (대시보드가 에러 없이 로드되도록)"""
    print("  [!] SUPABASE_URL/SUPABASE_KEY 미설정 → 빈 샘플 데이터 생성", flush=True)

    cve_data = []
    bl_data = {"date": dt.date.today().isoformat(), "snapshots": [], "indicators": [], "recovered": []}
    stats = export_stats(cve_data, bl_data)

    for filename, data in [("cves.json", cve_data), ("blacklist.json", bl_data), ("stats.json", stats)]:
        path = os.path.join(data_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  {filename} → {path}", flush=True)


def main():
    print("=== Dashboard Data Export ===", flush=True)
    client = _get_client()

    # docs/data 디렉토리 확인
    data_dir = os.path.join(os.path.dirname(_THIS_DIR), "docs", "data")
    os.makedirs(data_dir, exist_ok=True)

    # Supabase 자격증명 없으면 샘플 데이터 생성
    if client is None:
        _generate_sample_data(data_dir)
        print("=== Export 완료 (샘플 데이터) ===", flush=True)
        return

    # CVE 데이터
    print("[1/3] CVE 데이터 export...", flush=True)
    cve_data = export_cves(client)
    cve_path = os.path.join(data_dir, "cves.json")
    with open(cve_path, "w", encoding="utf-8") as f:
        json.dump(cve_data, f, ensure_ascii=False, indent=2)
    print(f"  CVE: {len(cve_data)}건 → {cve_path}", flush=True)

    # 블랙리스트 데이터
    print("[2/3] 블랙리스트 IP 데이터 export...", flush=True)
    bl_data = export_blacklist(client)
    bl_path = os.path.join(data_dir, "blacklist.json")
    with open(bl_path, "w", encoding="utf-8") as f:
        json.dump(bl_data, f, ensure_ascii=False, indent=2)
    print(f"  Blacklist: {len(bl_data.get('indicators', []))}건 → {bl_path}", flush=True)

    # 통계
    print("[3/3] 통계 집계...", flush=True)
    stats = export_stats(cve_data, bl_data)
    stats_path = os.path.join(data_dir, "stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"  Stats → {stats_path}", flush=True)

    print("=== Export 완료 ===", flush=True)


if __name__ == "__main__":
    main()