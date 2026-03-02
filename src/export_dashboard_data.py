"""
GitHub Pages 대시보드용 데이터 Export

Supabase에서 CVE/Shield 데이터를 조회하여
docs/data/*.json 정적 파일로 생성한다.
브라우저에서 직접 Supabase를 호출하지 않으므로 free tier 안전.
"""

import csv
import io
import os
import sys
import json
import datetime as dt
from collections import defaultdict

import requests

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
        # 어제 Critical/High IP 전체 조회 (페이지네이션)
        yesterday_highrisk: dict = {}
        page_size = 1000
        offset = 0
        while True:
            yesterday_res = client.table("shield_indicators") \
                .select("indicator, final_score, risk, category") \
                .eq("date", yesterday_date) \
                .in_("risk", ["Critical", "High"]) \
                .order("final_score", desc=True) \
                .range(offset, offset + page_size - 1) \
                .execute()

            rows = yesterday_res.data or []
            for r in rows:
                yesterday_highrisk[r["indicator"]] = r
            if len(rows) < page_size:
                break
            offset += page_size

        if not yesterday_highrisk:
            return []

        # 오늘 데이터에서 해당 IP들 조회 (IN 쿼리 100개씩 분할)
        today_ips = list(yesterday_highrisk.keys())
        today_map: dict = {}
        chunk_size = 100
        for i in range(0, len(today_ips), chunk_size):
            chunk = today_ips[i:i + chunk_size]
            today_res = client.table("shield_indicators") \
                .select("indicator, final_score, risk") \
                .eq("date", today_date) \
                .in_("indicator", chunk) \
                .execute()
            for r in (today_res.data or []):
                today_map[r["indicator"]] = r

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


# ─────────────────────────────────────────────
# External IOC Feed Collection (URL / Hash)
# ─────────────────────────────────────────────
_FEED_TIMEOUT = 30


def _collect_urlhaus() -> list:
    """URLhaus 온라인 악성 URL 수집 (CSV)"""
    url = "https://urlhaus.abuse.ch/downloads/csv_online/"
    r = requests.get(url, timeout=_FEED_TIMEOUT)
    r.raise_for_status()

    items = []
    reader = csv.reader(io.StringIO(r.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 7:
            continue
        # columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
        mal_url = row[2].strip().strip('"')
        if not mal_url or not mal_url.startswith(("http://", "https://")):
            continue
        threat = row[5].strip().strip('"')
        tags_raw = row[6].strip().strip('"')
        date_added = row[1].strip().strip('"')

        tag_list = [t.strip() for t in tags_raw.split(",") if t.strip()] if tags_raw else []
        items.append({
            "ioc_type": "url",
            "indicator": mal_url,
            "title": f"URLhaus - {threat}" if threat else "URLhaus - Malicious URL",
            "risk": "High",
            "score": 75,
            "date": date_added,
            "detail": {
                "source": "URLhaus",
                "threat": threat,
                "tags": tag_list,
            },
            "tags": ["URLhaus"] + ([threat] if threat else []),
        })

    return items


def _collect_malwarebazaar() -> list:
    """MalwareBazaar 최근 악성코드 해시 수집 (CSV)"""
    url = "https://bazaar.abuse.ch/export/csv/recent/"
    r = requests.get(url, timeout=_FEED_TIMEOUT)
    r.raise_for_status()

    items = []
    reader = csv.reader(io.StringIO(r.text))
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        if len(row) < 9:
            continue
        # columns: first_seen_utc, sha256_hash, md5_hash, sha1_hash, reporter,
        #          file_name, file_type_guess, mime_type, signature, ...
        first_seen = row[0].strip().strip('"')
        sha256 = row[1].strip().strip('"')
        file_name = row[5].strip().strip('"') if len(row) > 5 else ""
        file_type = row[6].strip().strip('"') if len(row) > 6 else ""
        signature = row[8].strip().strip('"') if len(row) > 8 else ""

        if not sha256 or len(sha256) != 64:
            continue

        title = f"MalwareBazaar - {signature}" if signature else "MalwareBazaar - Malware Sample"
        tag_list = ["MalwareBazaar"]
        if signature:
            tag_list.append(signature)
        if file_type:
            tag_list.append(file_type)

        items.append({
            "ioc_type": "hash",
            "indicator": sha256,
            "title": title,
            "risk": "High",
            "score": 80,
            "date": first_seen,
            "detail": {
                "source": "MalwareBazaar",
                "sha256": sha256,
                "file_name": file_name,
                "file_type": file_type,
                "signature": signature,
            },
            "tags": tag_list,
        })

    return items


def _collect_phishtank() -> list:
    """PhishTank 온라인 피싱 URL 수집 (CSV)"""
    url = "http://data.phishtank.com/data/online-valid.csv"
    r = requests.get(url, timeout=_FEED_TIMEOUT, headers={"User-Agent": "Argus-TI/1.0"})
    r.raise_for_status()

    items = []
    reader = csv.reader(io.StringIO(r.text))
    header_skipped = False
    for row in reader:
        if not header_skipped:
            header_skipped = True
            continue
        if not row or len(row) < 8:
            continue
        # columns: phish_id, url, phish_detail_url, submission_time, verified,
        #          verification_time, online, target
        phish_url = row[1].strip()
        submission_time = row[3].strip()
        target = row[7].strip() if len(row) > 7 else ""

        if not phish_url or not phish_url.startswith(("http://", "https://")):
            continue

        title = f"PhishTank - {target}" if target else "PhishTank - Phishing URL"
        items.append({
            "ioc_type": "url",
            "indicator": phish_url,
            "title": title,
            "risk": "Medium",
            "score": 60,
            "date": submission_time,
            "detail": {
                "source": "PhishTank",
                "target": target,
            },
            "tags": ["PhishTank", "phishing"] + ([target] if target else []),
        })

    return items


def collect_external_ioc_feeds() -> list:
    """URLhaus, MalwareBazaar, PhishTank 피드에서 IOC 수집"""
    all_items = []

    feeds = [
        ("URLhaus", _collect_urlhaus),
        ("MalwareBazaar", _collect_malwarebazaar),
        ("PhishTank", _collect_phishtank),
    ]

    for name, collector_fn in feeds:
        try:
            items = collector_fn()
            all_items.extend(items)
            print(f"  {name}: {len(items)}건 수집", flush=True)
        except Exception as e:
            print(f"  [!] {name} 수집 실패 (무시): {e}", flush=True)

    return all_items


def export_ioc(cve_data: list, blacklist_data: dict, external_iocs: list = None) -> dict:
    """CVE + IP + 탐지 룰을 통합 IOC 데이터로 변환 (타입별 분리)"""
    now = dt.datetime.now(dt.timezone.utc)

    # 타입별 버킷
    buckets: dict[str, list] = {"cve": [], "ip": [], "rule": [], "url": [], "hash": []}

    # 1) CVE → IOC
    for cve in cve_data:
        risk = cve.get("severity", "None")
        if risk == "None":
            risk = "Low"

        buckets["cve"].append({
            "ioc_type": "cve",
            "indicator": cve["id"],
            "title": cve.get("title", "N/A"),
            "risk": risk,
            "score": cve.get("cvss", 0),
            "date": cve.get("date", ""),
            "detail": {
                "cvss": cve.get("cvss", 0),
                "epss": cve.get("epss", 0),
                "is_kev": cve.get("is_kev", False),
                "cwe": cve.get("cwe", []),
                "affected": cve.get("affected", []),
                "has_poc": cve.get("has_poc", False),
                "report_url": cve.get("report_url"),
            },
            "tags": _build_cve_tags(cve),
            "related_rules": cve.get("rule_engines", []),
        })

    # 2) IP → IOC
    for ind in blacklist_data.get("indicators", []):
        buckets["ip"].append({
            "ioc_type": "ip",
            "indicator": ind["indicator"],
            "title": f"{ind.get('category', 'unknown')} ({', '.join(ind.get('sources', [])[:2])})",
            "risk": ind.get("risk", "Low"),
            "score": ind.get("score", 0),
            "date": blacklist_data.get("date", ""),
            "detail": {
                "category": ind.get("category", "unknown"),
                "sources": ind.get("sources", []),
                "abuse_confidence": ind.get("abuse_confidence"),
                "abuse_reports": ind.get("abuse_reports"),
            },
            "tags": _build_ip_tags(ind),
        })

    # 3) 탐지 룰 → IOC (CVE에 연결된 룰을 독립 IOC로도 등록)
    _KNOWN_ENGINES = {"sigma", "snort", "suricata", "yara"}
    for cve in cve_data:
        rules = cve.get("rules", {})
        if not rules:
            continue
        for engine, rule_content in rules.items():
            if engine not in _KNOWN_ENGINES or not rule_content:
                continue
            is_official = cve.get("has_official_rules", False)
            buckets["rule"].append({
                "ioc_type": "rule",
                "indicator": f"{cve['id']}:{engine}",
                "title": f"{engine.upper()} rule for {cve['id']}",
                "risk": cve.get("severity", "Low") if cve.get("severity") != "None" else "Low",
                "score": cve.get("cvss", 0),
                "date": cve.get("date", ""),
                "detail": {
                    "engine": engine,
                    "cve_id": cve["id"],
                    "is_official": is_official,
                    "rule_preview": rule_content[:500] if isinstance(rule_content, str) else "",
                    "report_url": cve.get("report_url"),
                },
                "tags": ["official" if is_official else "ai-generated", engine],
            })

    # 4) 외부 IOC 피드 (URLhaus, MalwareBazaar, PhishTank)
    if external_iocs:
        for item in external_iocs:
            t = item.get("ioc_type", "url")
            if t in buckets:
                buckets[t].append(item)
            else:
                buckets.setdefault(t, []).append(item)

    # 각 버킷 정렬 (최신 우선)
    for items in buckets.values():
        items.sort(key=lambda x: x.get("date", ""), reverse=True)

    # 통계 집계
    type_counts = {}
    risk_counts = defaultdict(int)
    total = 0
    for t, items in buckets.items():
        type_counts[t] = len(items)
        total += len(items)
        for item in items:
            risk_counts[item.get("risk", "Low")] += 1

    meta = {
        "generated_at": now.isoformat(),
        "total": total,
        "by_type": type_counts,
        "by_risk": dict(risk_counts),
    }

    return {"meta": meta, "buckets": buckets}


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


def _build_ip_tags(ind: dict) -> list:
    """IP indicator에서 태그 목록 생성"""
    tags = []
    cat = ind.get("category", "")
    if cat:
        tags.append(cat)
    source_count = len(ind.get("sources", []))
    if source_count >= 3:
        tags.append("multi-source")
    abuse = ind.get("abuse_confidence")
    if abuse is not None and abuse >= 80:
        tags.append("high-abuse")
    return tags


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


def _write_ioc_files(data_dir: str, ioc_result: dict):
    """IOC 데이터를 타입별 분리 파일로 출력"""
    meta = ioc_result["meta"]
    buckets = ioc_result["buckets"]

    # ioc-meta.json (경량 — 통계만, 대시보드 초기 로드용)
    meta_path = os.path.join(data_dir, "ioc-meta.json")
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, separators=(",", ":"))
    print(f"  ioc-meta.json → {meta_path}", flush=True)

    # 타입별 파일 (ioc-cve.json, ioc-ip.json, ...)
    for ioc_type, items in buckets.items():
        filename = f"ioc-{ioc_type}.json"
        path = os.path.join(data_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(items, f, ensure_ascii=False, separators=(",", ":"))
        print(f"  {filename}: {len(items)}건 → {path}", flush=True)


def _generate_sample_data(data_dir: str):
    """Supabase 자격증명 없을 때 빈 샘플 데이터 생성 (대시보드가 에러 없이 로드되도록)"""
    print("  [!] SUPABASE_URL/SUPABASE_KEY 미설정 → 빈 샘플 데이터 생성", flush=True)

    cve_data = []
    bl_data = {"date": dt.date.today().isoformat(), "snapshots": [], "indicators": [], "recovered": []}
    stats = export_stats(cve_data, bl_data)
    ioc_result = export_ioc(cve_data, bl_data)

    for filename, data in [("cves.json", cve_data), ("blacklist.json", bl_data), ("stats.json", stats)]:
        path = os.path.join(data_dir, filename)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"  {filename} → {path}", flush=True)

    _write_ioc_files(data_dir, ioc_result)


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
    print("[1/5] CVE 데이터 export...", flush=True)
    cve_data = export_cves(client)
    cve_path = os.path.join(data_dir, "cves.json")
    with open(cve_path, "w", encoding="utf-8") as f:
        json.dump(cve_data, f, ensure_ascii=False, indent=2)
    print(f"  CVE: {len(cve_data)}건 → {cve_path}", flush=True)

    # 블랙리스트 데이터
    print("[2/5] 블랙리스트 IP 데이터 export...", flush=True)
    bl_data = export_blacklist(client)
    bl_path = os.path.join(data_dir, "blacklist.json")
    with open(bl_path, "w", encoding="utf-8") as f:
        json.dump(bl_data, f, ensure_ascii=False, indent=2)
    print(f"  Blacklist: {len(bl_data.get('indicators', []))}건 → {bl_path}", flush=True)

    # 외부 IOC 피드 수집 (URLhaus, MalwareBazaar, PhishTank)
    print("[3/5] 외부 IOC 피드 수집...", flush=True)
    external_iocs = collect_external_ioc_feeds()
    print(f"  외부 IOC 합계: {len(external_iocs)}건", flush=True)

    # IOC 통합 데이터 (타입별 분리 파일)
    print("[4/5] IOC 통합 데이터 export (타입별 분리)...", flush=True)
    ioc_result = export_ioc(cve_data, bl_data, external_iocs=external_iocs)
    _write_ioc_files(data_dir, ioc_result)
    print(f"  IOC 합계: {ioc_result['meta']['total']}건", flush=True)

    # 통계
    print("[5/5] 통계 집계...", flush=True)
    stats = export_stats(cve_data, bl_data)
    stats_path = os.path.join(data_dir, "stats.json")
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    print(f"  Stats → {stats_path}", flush=True)

    print("=== Export 완료 ===", flush=True)


if __name__ == "__main__":
    main()