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
import pages
import risk
from weekly_report import publish_weekly_report


_SINGLE_RULE_KEYS = ("sigma", "nuclei", "splunk", "yara")


def _flat_ssvc(state: dict) -> dict:
    nested = state.get("ssvc")
    if not isinstance(nested, dict):
        return {}
    out = {}
    for key in ("exploitation", "automatable", "technical_impact"):
        v = state.get(f"ssvc_{key}") or nested.get(key)
        if isinstance(v, str) and v.strip():
            out[f"ssvc_{key}"] = v.strip().lower()
    return out


def _tier_of(state: dict, entry: dict) -> str:
    derived = risk.evaluate({
        **state,
        **_flat_ssvc(state),
        "is_kev": entry.get("is_kev", False),
        "cvss": entry.get("cvss", 0) or 0,
        "epss": entry.get("epss", 0) or 0,
    }).tier
    stored = _s(state, "tier")
    if stored not in (risk.T0, risk.T1, risk.T2, risk.T3):
        return derived
    return min(stored, derived, key=risk.tier_rank)


_EXPORT_SCHEMA = 2
_MAX_REFERENCES = 8
_ANALYSIS_KEYS = ("root_cause", "scenario", "impact")


def _analysis_of(state: dict, tier: str) -> dict:
    if tier not in risk.ALERTING_TIERS:
        return {}
    raw = state.get("analysis")
    if not isinstance(raw, dict):
        return {}
    out = {}
    for key in _ANALYSIS_KEYS:
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            out[key] = value.strip()
    steps = [s.strip() for s in (raw.get("mitigation") or [])
             if isinstance(s, str) and s.strip()]
    if steps:
        out["mitigation"] = steps[:6]
    return out


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


def export_cves(client, days: int = 90, since: str = None) -> list:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()

    rows = []
    page_size = 1000
    offset = 0
    while True:
        query = client.table("cves") \
            .select("id, cvss_score, epss_score, is_kev, has_official_rules, last_alert_at, last_alert_state, rules_snapshot, updated_at") \
            .gte("updated_at", since or cutoff) \
            .not_.is_("last_alert_state", "null")
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
            "date": row.get("last_alert_at") or row.get("updated_at") or "",
            "updated": row.get("updated_at") or "",
        }

        seen_aff = {}
        for aff in _l(state, "affected"):
            if not isinstance(aff, dict):
                continue
            vendor = _s(aff, "vendor", "Unknown")
            product = _s(aff, "product", "Unknown")
            versions = _s(aff, "versions")
            key = (vendor.strip().lower(), product.strip().lower())
            if key in seen_aff:
                prev = seen_aff[key]
                if versions and versions not in ("정보 없음", "") and versions not in prev["versions"]:
                    prev["versions"] = f"{prev['versions']}, {versions}" if prev["versions"] else versions
                continue
            item = {"vendor": vendor, "product": product, "versions": versions}
            seen_aff[key] = item
            entry["affected"].append(item)

        rules = row.get("rules_snapshot") or {}
        rule_engines = []
        for key in _SINGLE_RULE_KEYS:
            if rules.get(key):
                rule_engines.append(key)
        for net_rule in (rules.get("network") or []):
            engine = net_rule.get("engine") or "network"
            if engine not in rule_engines:
                rule_engines.append(engine)
        entry["rule_engines"] = rule_engines
        entry["has_official_rules"] = bool(row.get("has_official_rules"))
        if rule_engines:
            entry["rules"] = {
                k: rules[k] for k in _SINGLE_RULE_KEYS + ("network",) if rules.get(k)
            }

        state_poc = state.get("has_poc", False)
        entry["has_poc"] = state_poc
        entry["poc_urls"] = _l(state, "poc_urls")[:3]

        entry["degraded"] = bool(state.get("waf_degraded"))
        entry["cvss_vector"] = _s(state, "cvss_vector")
        entry["cvss_version"] = _s(state, "cvss_version")
        scores = state.get("cvss_scores")
        if isinstance(scores, dict) and len(scores) > 1:
            entry["cvss_alt"] = {k: v[0] for k, v in scores.items()
                                 if isinstance(v, (list, tuple)) and v}

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
        entry["kev_due_date"] = _s(state, "kev_due_date")[:10]
        entry["nuclei_severity"] = _s(state, "nuclei_severity")

        for key in ("_exploit_db_url", "_nuclei_url"):
            url = _s(state, key)
            if url:
                entry[key] = url

        refs = []
        for ref in _l(state, "references"):
            url = ref if isinstance(ref, str) else _s(ref, "url")
            url = url.strip()
            if url.startswith(("http://", "https://")) and url not in refs:
                refs.append(url)
            if len(refs) >= _MAX_REFERENCES:
                break
        if refs:
            entry["references"] = refs

        analysis = _analysis_of(state, entry["tier"])
        if analysis:
            entry["analysis"] = analysis

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


TABLE_AFFECTED = 3


def build_product_index(entries: list) -> dict:
    vend, prod, vers = {}, {}, {}


    def idx(table, value):
        value = (value or "").strip()
        if not value:
            return -1
        if value not in table:
            table[value] = len(table)
        return table[value]

    mapping = {}
    for e in entries:
        items = [[idx(vend, a.get("vendor")), idx(prod, a.get("product")),
                  idx(vers, a.get("versions"))]
                 for a in (e.get("affected") or []) if isinstance(a, dict)]
        if items:
            mapping[e.get("id", "")] = items
    return {
        "vendors": list(vend), "products": list(prod), "versions": list(vers),
        "map": mapping,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def decode_product_index(index: dict) -> dict:
    v, p, s = (index.get("vendors") or [], index.get("products") or [],
               index.get("versions") or [])


    def at(table, i):
        return table[i] if isinstance(i, int) and 0 <= i < len(table) else ""

    out = {}
    for cve, items in (index.get("map") or {}).items():
        out[cve] = [{"vendor": at(v, it[0]), "product": at(p, it[1]),
                     "versions": at(s, it[2])}
                    for it in items if isinstance(it, list) and len(it) >= 3]
    return out


def live_ids(client, days: int = 90):
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    found, offset, page_size = set(), 0, 1000
    while True:
        try:
            r = client.table("cves").select("id") \
                .gte("updated_at", cutoff) \
                .not_.is_("last_alert_state", "null") \
                .order("id").range(offset, offset + page_size - 1).execute()
        except Exception as e:
            print(f"  [!] id 목록 조회 실패({e}) → 이번 회차는 병합에서 제외하지 않는다",
                  flush=True)
            return None
        page = r.data or []
        found.update(row["id"] for row in page if row.get("id"))
        if len(page) < page_size:
            return found
        offset += page_size


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


def fetch_live_products() -> dict:
    try:
        payload = pages.fetch_published_json("cve-products.json", timeout=180)
        if payload is None:
            return {}
        return decode_product_index(payload)
    except Exception as e:
        print(f"  직전 제품 인덱스를 읽지 못함({e}) → 이번 회차분으로만 만든다", flush=True)
        return {}


def _fetch_live_export() -> tuple:
    try:
        rows = pages.fetch_published_json("cves.json", timeout=180)
        stats = pages.fetch_published_json("stats.json", timeout=180)
        generated_at = (stats or {}).get("generated_at")
        if isinstance(rows, list) and rows and generated_at:
            print(f"  직전 export를 배포본에서 읽음 ({len(rows)}건)", flush=True)
            return rows, generated_at, stats.get("schema")
    except Exception as e:
        print(f"  배포본을 읽지 못함({e}) → 체크아웃 사본 확인", flush=True)
    return None, None, None


def load_previous_export(data_dir: str) -> tuple:
    if os.environ.get("ARGUS_FULL_EXPORT") == "1":
        print("  ARGUS_FULL_EXPORT=1 → 전량 export", flush=True)
        return None, None
    try:
        rows, generated_at, schema = _fetch_live_export()
        if rows is None:
            with open(os.path.join(data_dir, "cves.json"), encoding="utf-8") as f:
                rows = json.load(f)
            with open(os.path.join(data_dir, "stats.json"), encoding="utf-8") as f:
                stats = json.load(f)
            generated_at, schema = stats.get("generated_at"), stats.get("schema")
        if not isinstance(rows, list) or not rows or not generated_at:
            return None, None
        if schema != _EXPORT_SCHEMA:
            print(f"  직전 export 스키마 {schema} ≠ 현재 {_EXPORT_SCHEMA} → 전량 export",
                  flush=True)
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


def merge_exports(previous: list, fresh: list, days: int = 90, keep=None) -> list:
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    by_id = {r.get("id"): r for r in previous if r.get("id")}
    for r in fresh:
        if r.get("id"):
            by_id[r["id"]] = r
    if keep is not None:
        dropped = [k for k in by_id if k not in keep]
        for k in dropped:
            del by_id[k]
        if dropped:
            print(f"  DB 에서 사라진 {len(dropped):,}건을 병합에서 제외", flush=True)
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
        "schema": _EXPORT_SCHEMA,
        "triggers": {key: t.label for key, t in risk.TRIGGERS.items()},
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
    tracked_now = _count(client, tracked=True)
    if tracked_now > max_rows:
        excess = tracked_now - max_rows
        window = cutoff(watch_days)
        victims = client.table("cves") \
            .select("id, is_kev, cvss_score, epss_score, last_alert_state") \
            .lt("updated_at", window) \
            .order("updated_at", desc=False).limit(excess * 2).execute()
        ids = [r["id"] for r in (victims.data or [])
               if r.get("id") and not _is_alerting_row(r)][:excess]
        for i in range(0, len(ids), 200):
            client.table("cves").delete().in_("id", ids[i:i + 200]).execute()
            capped += len(ids[i:i + 200])
        if capped < excess:
            print(f"  ⚠️ 추적 {tracked_now:,}행 > 상한 {max_rows:,} 이지만 "
                  f"{capped:,}건만 지울 수 있다 — 나머지는 {watch_days}일 안이거나 "
                  f"악용 중이라 보존한다. 물량이 계속 늘면 risk.py 임계를 조여야 한다",
                  flush=True)
        elif capped:
            print(f"  상한 초과 {capped:,}건 삭제 (추적 상한 {max_rows:,}행)", flush=True)

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
    fresh_ids = set()
    if previous is None:
        cve_data = export_cves(client)
        print(f"  전량 export: {len(cve_data)}건", flush=True)
    else:
        fresh = export_cves(client, since=since)
        fresh_ids = {r.get("id") for r in fresh if r.get("id")}
        cve_data = merge_exports(previous, fresh, keep=live_ids(client))
        print(f"  증분 export: 변경 {len(fresh)}건 → 병합 후 {len(cve_data)}건 "
              f"(직전 {len(previous)}건)", flush=True)
    carried = fetch_live_products() if previous is not None else {}
    merged_products = []
    restored = 0
    for e in cve_data:
        aff = e.get("affected") or []
        if e.get("id") not in fresh_ids:
            full = carried.get(e.get("id")) or []
            if len(full) > len(aff):
                restored += len(full) - len(aff)
                aff = full
                e["affected"] = aff
        merged_products.append({"id": e.get("id"), "affected": aff})
    if restored:
        print(f"  직전 인덱스에서 제품 항목 {restored:,}개 이어받음", flush=True)

    prod_index = build_product_index(merged_products)
    prod_path = os.path.join(data_dir, "cve-products.json")
    pages.write_json(prod_path, prod_index)
    total_items = sum(len(v) for v in prod_index["map"].values())
    print(f"  영향 제품 인덱스: {len(prod_index['map']):,}건 · 항목 {total_items:,}개 "
          f"(고유 제품 {len(prod_index['products']):,}) → {prod_path}", flush=True)

    for e in cve_data:
        aff = e.get("affected") or []
        if len(aff) > TABLE_AFFECTED:
            e["affected"] = aff[:TABLE_AFFECTED]
            e["affected_total"] = len(aff)

    cve_path = os.path.join(data_dir, "cves.json")
    pages.write_json(cve_path, cve_data)
    print(f"  CVE: {len(cve_data)}건 → {cve_path}", flush=True)

    print("[2/4] 통계 집계...", flush=True)
    stats = export_stats(cve_data)
    stats_path = os.path.join(data_dir, "stats.json")
    pages.write_json(stats_path, stats)
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
