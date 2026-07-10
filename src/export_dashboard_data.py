"""
GitHub Pages 대시보드용 데이터 Export

Supabase에서 CVE 데이터를 조회하여
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
            .select("id, cvss_score, epss_score, is_kev, has_official_rules, last_alert_at, last_alert_state, rules_snapshot, report_url, updated_at") \
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

        # 탐지 룰 정보
        rules = row.get("rules_snapshot") or {}
        rule_engines = []
        for engine in ["sigma", "snort", "suricata", "yara"]:
            if rules.get(engine):
                rule_engines.append(engine)
        entry["rule_engines"] = rule_engines
        entry["has_official_rules"] = row.get("has_official_rules", False)
        entry["rules"] = rules

        # PoC 정보
        state_poc = state.get("has_poc", False)
        entry["has_poc"] = state_poc
        entry["poc_urls"] = state.get("poc_urls", [])[:3]

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


def _build_cve_tags(cve: dict) -> list:
    """CVE에서 태그 목록 생성"""
    tags = []
    if cve.get("is_kev"):
        tags.append("KEV")
    if cve.get("has_poc"):
        tags.append("PoC")
    if cve.get("cvss", 0) >= 9.0:
        tags.append("Critical")
    if cve.get("epss", 0) >= 0.1:
        tags.append("High-EPSS")
    if cve.get("rule_engines"):
        tags.append("has-rules")
    if cve.get("has_official_rules"):
        tags.append("official-rules")
    return tags


def export_stats(cve_data: list) -> dict:
    """CVE 통계 집계"""
    now = dt.datetime.now(dt.timezone.utc)

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
    }


def apply_retention_policy(client, days: int = 180) -> int:
    """최근 N일 이전 레코드의 대용량 JSON 필드(rules_snapshot, last_alert_state)를 null 처리.

    상세 분석/룰 원문은 GitHub Issue에 영구 보존되므로 데이터 손실 없이
    Supabase free tier(500MB) 용량을 방어한다 (불변 원칙 2).
    """
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    response = client.table("cves") \
        .update({"rules_snapshot": None, "last_alert_state": None}) \
        .lt("updated_at", cutoff) \
        .not_.is_("last_alert_state", "null") \
        .execute()
    return len(response.data or [])


def _generate_sample_data(data_dir: str):
    """Supabase 자격증명 없을 때 빈 샘플 데이터 생성 (대시보드가 에러 없이 로드되도록)"""
    print("  [!] SUPABASE_URL/SUPABASE_KEY 미설정 → 빈 샘플 데이터 생성", flush=True)

    cve_data = []
    stats = export_stats(cve_data)

    for filename, data in [("cves.json", cve_data), ("stats.json", stats)]:
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

    # 통계
    print("[2/3] 통계 집계...", flush=True)
    stats = export_stats(cve_data)
    stats_path = os.path.join(data_dir, "stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"  Stats → {stats_path}", flush=True)

    # DB 보존 정책 (180일 지난 레코드의 대용량 필드 정리)
    print("[3/3] DB 보존 정책 적용...", flush=True)
    try:
        cleaned = apply_retention_policy(client)
        print(f"  {cleaned}건 정리 (rules_snapshot/last_alert_state null 처리)", flush=True)
    except Exception as e:
        print(f"  [!] DB 보존 정책 적용 실패: {e}", flush=True)

    print("=== Export 완료 ===", flush=True)


if __name__ == "__main__":
    main()
