import os
import re
import sys
import json
import datetime as dt
from collections import defaultdict

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from supabase import create_client
import risk
from weekly_report import publish_weekly_report


def _tier_of(state: dict, entry: dict) -> str:
    derived = risk.evaluate({
        **state,
        "is_kev": entry.get("is_kev", False),
        "cvss": entry.get("cvss", 0) or 0,
        "epss": entry.get("epss", 0) or 0,
    }).tier
    stored = _s(state, "tier")
    if stored not in (risk.T0, risk.T1, risk.T2, risk.T3):
        return derived
    return min(stored, derived, key=risk.tier_rank)


def _get_client():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not url or not key:
        return None
    return create_client(url, key)


def _s(state: dict, key: str, default: str = "") -> str:
    v = state.get(key)
    return v if isinstance(v, str) else default


def _l(state: dict, key: str) -> list:
    v = state.get(key)
    return v if isinstance(v, list) else []


def _write_json(path: str, payload) -> None:
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def export_cves(client, days: int = 90, since: str = None) -> list:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()

    rows = []
    page_size = 1000
    offset = 0
    while True:
        query = client.table("cves") \
            .select("id, cvss_score, epss_score, is_kev, has_official_rules, last_alert_at, last_alert_state, rules_snapshot, report_url, updated_at") \
            .gte("updated_at", since or cutoff) \
            .not_.is_("last_alert_state", "null")
        # 정렬 키는 id 다. updated_at 으로 정렬하면 안 된다 — fast-lane 이 5분마다 별도
        # 워크플로로 돌며 이 테이블에 쓰고, 그러면 페이지를 넘기는 사이에 행이 앞으로
        # 튀어 경계를 넘나든다. offset 페이징에서 그건 곧 '어떤 행은 건너뛰고 어떤 행은
        # 두 번 읽는다'는 뜻이고, 회차마다 결과 건수가 달라진다.
        response = query \
            .order("id") \
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

        cwe_clean = []
        for w in _l(state, "cwe"):
            for m in re.findall(r"CWE-\d{1,4}\b", str(w)):
                if m not in cwe_clean:
                    cwe_clean.append(m)

        title = _s(state, "title_ko") or _s(state, "title", "N/A")
        if title.strip() in ("해당 없음", "N/A", "정보 없음", ""):
            aff0 = next((a for a in _l(state, "affected")
                         if isinstance(a, dict) and a.get("product")
                         and str(a["product"]).lower() not in ("n/a", "unknown")), None)
            if aff0:
                title = f"{aff0['product']} 취약점"

        entry = {
            "id": row.get("id", ""),
            "title": title,
            "description": _s(state, "desc_ko") or _s(state, "description")[:300],
            "cvss": row.get("cvss_score", 0) or 0,
            "epss": row.get("epss_score", 0) or 0,
            "is_kev": bool(row.get("is_kev")),
            "cwe": cwe_clean,
            "affected": [],
            "report_url": row.get("report_url"),
            "date": row.get("last_alert_at") or row.get("updated_at") or "",
            "updated": row.get("updated_at") or "",
        }

        for aff in _l(state, "affected")[:3]:
            if not isinstance(aff, dict):
                continue
            entry["affected"].append({
                "vendor": _s(aff, "vendor", "Unknown"),
                "product": _s(aff, "product", "Unknown"),
                "versions": _s(aff, "versions"),
            })

        rules = row.get("rules_snapshot") or {}
        rule_engines = []
        if rules.get("sigma"):
            rule_engines.append("sigma")
        for net_rule in (rules.get("network") or []):
            engine = net_rule.get("engine") or "network"
            if engine not in rule_engines:
                rule_engines.append(engine)
        if rules.get("yara"):
            rule_engines.append("yara")
        entry["rule_engines"] = rule_engines
        entry["has_official_rules"] = bool(row.get("has_official_rules"))
        if rule_engines:
            entry["rules"] = {
                k: rules[k] for k in ("sigma", "network", "yara") if rules.get(k)
            }

        state_poc = state.get("has_poc", False)
        entry["has_poc"] = state_poc
        entry["poc_urls"] = _l(state, "poc_urls")[:3]

        entry["degraded"] = bool(state.get("waf_degraded"))
        entry["cvss_vector"] = _s(state, "cvss_vector")

        entry["ssvc_exploitation"] = state.get("ssvc_exploitation") or (state.get("ssvc") or {}).get("exploitation")
        entry["has_public_exploit"] = state.get("has_public_exploit", False)
        entry["has_metasploit_module"] = state.get("has_metasploit_module", False)
        entry["metasploit_modules"] = _l(state, "metasploit_modules")[:3]
        entry["has_nuclei_template"] = state.get("has_nuclei_template", False)
        entry["ai_discovered"] = state.get("ai_discovered", False)
        entry["ai_program"] = _s(state, "ai_program")
        entry["ai_detail"] = _s(state, "ai_detail")
        entry["ai_url"] = _s(state, "ai_url")
        entry["is_vulncheck_kev"] = state.get("is_vulncheck_kev", False)

        entry["tier"] = _tier_of(state, entry)
        entry["triggers"] = [t for t in _l(state, "fired_triggers") if isinstance(t, str)]
        entry["epss_percentile"] = state.get("epss_percentile") or 0

        ssvc = state.get("ssvc") or {}
        entry["ssvc_automatable"] = state.get("ssvc_automatable") or ssvc.get("automatable")
        entry["ssvc_technical_impact"] = state.get("ssvc_technical_impact") or ssvc.get("technical_impact")
        entry["is_kev_ransomware"] = state.get("is_kev_ransomware", False)

        entry["published"] = _s(state, "published")[:10]

        entry["is_kernel"] = any(
            _s(a, "vendor").strip().lower() == "linux" for a in entry["affected"]
        )

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


_FULL_EXPORT_MAX_AGE_H = 24


def _take_full_export_flag(client) -> bool:
    try:
        r = client.table("pipeline_state").select("state").eq("id", 1).limit(1).execute()
        st = ((r.data or [{}])[0] or {}).get("state") or {}
        if not st.get("force_full_export"):
            return False
        st.pop("force_full_export", None)
        client.table("pipeline_state").upsert({"id": 1, "state": st}).execute()
        return True
    except Exception as e:
        print(f"  전량 export 표시 확인 실패(무시): {e}", flush=True)
        return False


def _fetch_live_export() -> tuple:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None, None
    owner, name = repo.split("/", 1)
    base = f"https://{owner.lower()}.github.io/{name}/data"
    try:
        import urllib.request

        def get(fn):
            req = urllib.request.Request(f"{base}/{fn}", headers={"User-Agent": "argus-export"})
            with urllib.request.urlopen(req, timeout=180) as r:
                return json.loads(r.read().decode("utf-8"))

        rows = get("cves.json")
        generated_at = get("stats.json").get("generated_at")
        if isinstance(rows, list) and rows and generated_at:
            print(f"  직전 export를 배포본에서 읽음 ({len(rows)}건)", flush=True)
            return rows, generated_at
    except Exception as e:
        print(f"  배포본을 읽지 못함({e}) → 체크아웃 사본 확인", flush=True)
    return None, None


def load_previous_export(data_dir: str) -> tuple:
    if os.environ.get("ARGUS_FULL_EXPORT") == "1":
        print("  ARGUS_FULL_EXPORT=1 → 전량 export", flush=True)
        return None, None
    try:
        rows, generated_at = _fetch_live_export()
        if rows is None:
            with open(os.path.join(data_dir, "cves.json"), encoding="utf-8") as f:
                rows = json.load(f)
            with open(os.path.join(data_dir, "stats.json"), encoding="utf-8") as f:
                generated_at = json.load(f).get("generated_at")
        if not isinstance(rows, list) or not rows or not generated_at:
            return None, None
        if not any(r.get("updated") for r in rows[:50]):
            print("  직전 파일에 병합 기준(updated)이 없음 → 전량 export", flush=True)
            return None, None
        prev = dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
        age_h = (dt.datetime.now(dt.timezone.utc) - prev).total_seconds() / 3600
        if age_h > _FULL_EXPORT_MAX_AGE_H:
            print(f"  직전 export가 {age_h:.0f}시간 전 → 전량 export로 재동기화", flush=True)
            return None, None
        return rows, (prev - dt.timedelta(minutes=10)).isoformat()
    except Exception as e:
        print(f"  직전 export를 읽지 못함({e}) → 전량 export", flush=True)
        return None, None


def merge_exports(previous: list, fresh: list, days: int = 90) -> list:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    by_id = {r.get("id"): r for r in previous if r.get("id")}
    for r in fresh:
        if r.get("id"):
            by_id[r["id"]] = r
    merged = [r for r in by_id.values() if (r.get("updated") or "") >= cutoff]
    merged.sort(key=lambda r: r.get("updated") or "", reverse=True)
    return merged


def export_stats(cve_data: list) -> dict:
    now = dt.datetime.now(dt.timezone.utc)

    severity_counts = defaultdict(int)
    vendor_counts = defaultdict(int)
    product_counts = defaultdict(int)
    product_vendor = {}
    daily_counts = defaultdict(int)
    recent_24h = 0
    kev_count = 0
    kernel_count = 0

    def _clean(v: str) -> str:
        v = (v or "").strip()
        return "" if v.lower() in ("", "unknown", "n/a", "-") else v

    for cve in cve_data:
        severity_counts[cve.get("severity", "None")] += 1

        if cve.get("is_kev"):
            kev_count += 1

        pub = (cve.get("published") or "")[:10]
        if pub:
            daily_counts[pub] += 1

        date_str = cve.get("date", "")
        if date_str:
            try:
                cve_dt = dt.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if (now - cve_dt).total_seconds() < 86400:
                    recent_24h += 1
            except (ValueError, TypeError):
                pass

        if cve.get("is_kernel"):
            kernel_count += 1
            continue

        seen_v, seen_p = set(), set()
        for aff in cve.get("affected", []):
            vendor, product = _clean(aff.get("vendor")), _clean(aff.get("product"))
            if vendor and vendor not in seen_v:
                vendor_counts[vendor] += 1
                seen_v.add(vendor)
            if product and product not in seen_p:
                product_counts[product] += 1
                seen_p.add(product)
                if vendor:
                    product_vendor.setdefault(product, vendor)

    today = now.date()
    daily_trend = []
    for i in range(29, -1, -1):
        day = (today - dt.timedelta(days=i)).isoformat()
        daily_trend.append((day, daily_counts.get(day, 0)))

    trend_covered = sum(daily_counts.values())

    product_top = sorted(product_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    vendor_top = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "generated_at": now.isoformat(),
        "cve": {
            "total": len(cve_data),
            "recent_24h": recent_24h,
            "kev_count": kev_count,
            "kernel_count": kernel_count,
            "severity": dict(severity_counts),
            "daily_trend": [{"date": d, "count": c} for d, c in daily_trend],
            "trend_covered": trend_covered,
            "top_products": [{"product": p, "vendor": product_vendor.get(p, ""), "count": c}
                             for p, c in product_top],
            "top_vendors": [{"vendor": v, "count": c} for v, c in vendor_top],
        },
    }


def _is_alerting_row(row: dict) -> bool:
    """지금도 악용 중이거나 무기화된 건인가 — 보존 정책이 지우면 안 되는 행.

    저장된 티어와 신호에서 유도한 티어 중 더 위험한 쪽으로 본다(_tier_of 와 같은 규칙).
    오래돼서 지우는 것과 위험해서 남기는 것이 부딪히면 남기는 쪽이 맞다."""
    state = row.get("last_alert_state") or {}
    entry = {"is_kev": bool(row.get("is_kev") or state.get("is_kev")),
             "cvss": row.get("cvss_score") or 0, "epss": row.get("epss_score") or 0}
    return risk.is_alerting(_tier_of(state, entry))


def apply_retention_policy(client, days: int = 120, marker_days: int = 30,
                           delete_days: int = 180, watch_days: int = 90,
                           max_rows: int = 20000) -> int:
    now = dt.datetime.now(dt.timezone.utc)

    def cutoff(n):
        return (now - dt.timedelta(days=n)).isoformat()

    cleaned = 0
    stale = client.table("cves").select("id, is_kev, cvss_score, epss_score, last_alert_state") \
        .lt("updated_at", cutoff(days)) \
        .not_.is_("last_alert_state", "null") \
        .execute()
    blank = [r["id"] for r in (stale.data or []) if r.get("id") and not _is_alerting_row(r)]
    for i in range(0, len(blank), 200):
        client.table("cves") \
            .update({"rules_snapshot": None, "last_alert_state": None}) \
            .in_("id", blank[i:i + 200]).execute()
        cleaned += len(blank[i:i + 200])

    deleted = client.table("cves") \
        .delete() \
        .is_("last_alert_state", "null") \
        .is_("last_alert_at", "null") \
        .lt("updated_at", cutoff(marker_days)) \
        .execute()
    deleted_count = len(deleted.data or [])
    if deleted_count:
        print(f"  구 마커 {deleted_count}건 청소 ({marker_days}일 경과)", flush=True)

    # 이 쓸기는 원래 '관찰(T2)에 오래 신호가 안 붙은 행'을 겨냥한 것이고, 그 판별을
    # last_alert_at IS NULL 로 대신했다. 그런데 소급 채우기(backfill_exploited, silent=True)가
    # 들어오면서 그 전제가 깨졌다 — 지금 악용 중인 T0 행도 last_alert_at 이 비어 있다.
    # 2015~2020년 KEV처럼 레코드가 더는 안 바뀌는 건은 90일이면 그대로 지워진다.
    # 그래서 조건으로 거르지 않고, 후보를 받아 티어를 확인한 뒤 지운다.
    watch_count = 0
    cand = client.table("cves").select("id, is_kev, cvss_score, epss_score, last_alert_state") \
        .is_("last_alert_at", "null") \
        .lt("updated_at", cutoff(watch_days)) \
        .execute()
    victims = [r["id"] for r in (cand.data or [])
               if r.get("id") and not _is_alerting_row(r)]
    kept = len(cand.data or []) - len(victims)
    for i in range(0, len(victims), 200):
        client.table("cves").delete().in_("id", victims[i:i + 200]).execute()
        watch_count += len(victims[i:i + 200])
    if watch_count or kept:
        print(f"  관찰 {watch_count}건 만료 삭제 ({watch_days}일간 신호 없음)"
              f"{f' · 악용 중이라 보존 {kept}건' if kept else ''}", flush=True)

    purged_count = 0
    old_rows = client.table("cves").select("id, is_kev, cvss_score, epss_score, last_alert_state") \
        .lt("updated_at", cutoff(delete_days)).execute()
    gone = [r["id"] for r in (old_rows.data or []) if r.get("id") and not _is_alerting_row(r)]
    for i in range(0, len(gone), 200):
        client.table("cves").delete().in_("id", gone[i:i + 200]).execute()
        purged_count += len(gone[i:i + 200])
    if purged_count:
        print(f"  오래된 행 {purged_count}건 삭제 ({delete_days}일 경과)", flush=True)

    capped = 0
    total = _count(client)
    if total > max_rows:
        excess = total - max_rows
        victims = client.table("cves").select("id, is_kev, cvss_score, epss_score, last_alert_state") \
            .order("updated_at", desc=False).limit(excess * 2).execute()
        ids = [r["id"] for r in (victims.data or [])
               if r.get("id") and not _is_alerting_row(r)][:excess]
        for i in range(0, len(ids), 200):
            client.table("cves").delete().in_("id", ids[i:i + 200]).execute()
            capped += len(ids[i:i + 200])
        print(f"  상한 초과 {capped}건 삭제 (상한 {max_rows:,}행)", flush=True)

    tracked = _count(client, tracked=True)
    remaining = _count(client)
    print(f"  현황: 전체 {remaining:,} · 추적 {tracked:,} · 상태없음 {remaining - tracked:,} "
          f"· 이번 삭제 {deleted_count + watch_count + purged_count + capped:,}", flush=True)

    return cleaned


def _count(client, tracked: bool = False) -> int:
    try:
        q = client.table("cves").select("id", count="exact").limit(1)
        if tracked:
            q = q.not_.is_("last_alert_state", "null")
        return q.execute().count or 0
    except Exception as e:
        print(f"  [!] 행 수 조회 실패(무시): {e}", flush=True)
        return 0


def _generate_sample_data(data_dir: str):
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

    data_dir = os.path.join(os.path.dirname(_THIS_DIR), "docs", "data")
    os.makedirs(data_dir, exist_ok=True)

    if client is None:
        _generate_sample_data(data_dir)
        print("=== Export 완료 (샘플 데이터) ===", flush=True)
        return

    print("[1/4] CVE 데이터 export...", flush=True)
    if _take_full_export_flag(client):
        print("  백필 반영 요청 있음 → 이번은 전량 export", flush=True)
        previous, since = None, None
    else:
        previous, since = load_previous_export(data_dir)
    if previous is None:
        cve_data = export_cves(client)
        print(f"  전량 export: {len(cve_data)}건", flush=True)
    else:
        fresh = export_cves(client, since=since)
        cve_data = merge_exports(previous, fresh)
        print(f"  증분 export: 변경 {len(fresh)}건 → 병합 후 {len(cve_data)}건 "
              f"(직전 {len(previous)}건)", flush=True)
    cve_path = os.path.join(data_dir, "cves.json")
    _write_json(cve_path, cve_data)
    print(f"  CVE: {len(cve_data)}건 → {cve_path}", flush=True)

    print("[2/4] 통계 집계...", flush=True)
    stats = export_stats(cve_data)
    stats_path = os.path.join(data_dir, "stats.json")
    _write_json(stats_path, stats)
    print(f"  Stats → {stats_path}", flush=True)

    print("[3/4] 주간 리포트 확인...", flush=True)
    try:
        publish_weekly_report(cve_data)
    except Exception as e:
        print(f"  [!] 주간 리포트 생성 실패(무시): {e}", flush=True)

    print("[4/4] DB 보존 정책 적용...", flush=True)
    try:
        cleaned = apply_retention_policy(client)
        print(f"  {cleaned}건 정리 (rules_snapshot/last_alert_state null 처리)", flush=True)
    except Exception as e:
        print(f"  [!] DB 보존 정책 적용 실패: {e}", flush=True)

    print("=== Export 완료 ===", flush=True)


if __name__ == "__main__":
    main()
