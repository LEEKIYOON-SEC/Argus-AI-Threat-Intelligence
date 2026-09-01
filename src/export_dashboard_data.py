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

        # 영향 제품은 **전량**을 싣는다. 예전에는 3개로 잘랐는데, 실측(664건)으로 CVE 의
        # 51.9%가 3개를 넘고 전체 제품 항목의 71%가 잘려 나갔다. 그 상태로는 '내가 쓰는
        # 제품이 영향받나'를 검색으로 확인할 수 없다 — 8번째에 있으면 안 나온다.
        # (예: CVE-2026-14164 는 23개 중 OpenShift 가 8번째라 검색에 안 걸렸다)
        # 같은 vendor+product 가 스트림별로 여러 줄 오므로 버전 문자열을 합쳐 접는다.
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


#: 목록 표에 그대로 싣는 영향 제품 수. 나머지는 cve-products.json 에서 찾는다.
TABLE_AFFECTED = 3


def build_product_index(entries: list) -> dict:
    """영향 제품 역인덱스 — 이름을 사전에 한 번만 담고 CVE 는 번호만 참조한다.

    왜 따로 파일로 빼는가: 영향 제품을 자르지 않고 cves.json 에 그대로 실으면 실측
    12.3MB 가 더 붙는다(현재 배포본이 이미 22.7MB). 그런데 제품 이름은 지독하게
    반복된다 — 표본 664건에서 제품 항목 4,653개가 고유 이름으로는 321개뿐이었다.
    사전으로 접으면 같은 정보가 1.6MB(gzip 0.2MB)에 들어간다.
    """
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
    """{CVE: [{vendor, product, versions}, …]} 로 되돌린다 (병합·검증용)."""
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
    """지금 DB 에 있는(대시보드에 실려야 할) CVE id 전량. **조회 실패면 None.**

    증분 export 의 병합은 `직전 배포본 ∪ 이번에 바뀐 행`이라, DB 에서 사라진 행을
    스스로 지우지 못한다. 그래서 다음이 벌어졌다.

      번역이 돌면  → request_full_export() → 전량 export → 건수 = DB 실제
      번역이 안 돌면(Gemma 503 등) → 병합 → 건수 = 직전 배포본 ∪ 신규 (더 큼)

    '추적 중 CVE'가 회차마다 오르내린 이유가 이것이다. 두 경로가 같은 집합을 만들지
    않았다. id 만 받아 오면 13,000건에 200KB 남짓이라, 전량 export 를 다시 도는 것보다
    훨씬 싸게 회원 자격을 맞출 수 있다.

    None 을 돌려주는 것이 중요하다 — 조회 실패를 '전부 사라졌다'로 읽으면 대시보드가
    통째로 비워진다.
    """
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
    """배포 중인 제품 인덱스. 증분 export 는 바뀐 CVE 만 다시 만들므로, 나머지 CVE 의
    제품 목록은 여기서 이어받아야 한다 — 안 그러면 갱신 안 된 CVE 가 인덱스에서 사라진다."""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return {}
    owner, name = repo.split("/", 1)
    try:
        import urllib.request
        url = f"https://{owner.lower()}.github.io/{name}/data/cve-products.json"
        req = urllib.request.Request(url, headers={"User-Agent": "argus-export"})
        with urllib.request.urlopen(req, timeout=180) as r:
            return decode_product_index(json.loads(r.read().decode("utf-8")))
    except Exception as e:
        print(f"  직전 제품 인덱스를 읽지 못함({e}) → 이번 회차분으로만 만든다", flush=True)
        return {}


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


def merge_exports(previous: list, fresh: list, days: int = 90, keep=None) -> list:
    # keep = 지금 DB 에 있는 id 집합. None 이면 조회를 못 한 것이므로 아무것도 떨구지
    # 않는다(그걸 '전부 사라짐'으로 읽으면 대시보드가 비워진다).
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

    # 행수 상한. 두 가지를 지킨다.
    #
    #  ① 세는 대상은 **추적 행**이다. 예전에는 _count(client) 로 전체를 셌는데, 상태가
    #     비워진 옛 행까지 포함돼 상한에 먼저 닿았고, 그러면 오래된 순 삭제가 마커를
    #     다 먹은 뒤 **살아 있는 추적 행**으로 넘어갔다.
    #  ② 대시보드가 지금 보여주는 구간(90일) 안의 행은 지우지 않는다. 26일 된 KEV 를
    #     행수 때문에 지우면 '악용 중인 것을 빠짐없이 본다'는 목적 자체가 깨진다.
    #     상한에 걸리는데 지울 게 없으면 그건 risk.py 임계를 조일 신호지, 조용히
    #     지울 일이 아니다.
    #
    # 이게 '추적 중 CVE'가 오르내린 원인의 절반이었다 — DB 에서는 지워지는데 증분
    # 병합은 배포본을 이어받아 그대로 들고 있었고, 전량 export 때만 숫자가 떨어졌다.
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
    if previous is None:
        cve_data = export_cves(client)
        print(f"  전량 export: {len(cve_data)}건", flush=True)
    else:
        fresh = export_cves(client, since=since)
        cve_data = merge_exports(previous, fresh, keep=live_ids(client))
        print(f"  증분 export: 변경 {len(fresh)}건 → 병합 후 {len(cve_data)}건 "
              f"(직전 {len(previous)}건)", flush=True)
    # 영향 제품은 별도 파일(사전 압축)로 뺀다. cves.json 에 전량을 실으면 실측으로
    # 12.3MB 가 더 붙는다 — 이미 22.7MB 인 파일이라 감당이 안 된다.
    # 증분 export 는 바뀐 CVE 만 새로 만들므로, 나머지는 배포본 인덱스에서 이어받는다.
    carried = fetch_live_products() if previous is not None else {}
    merged_products = []
    for e in cve_data:
        aff = e.get("affected") or []
        if not aff and carried.get(e.get("id")):
            aff = carried[e["id"]]
            e["affected"] = aff
        merged_products.append({"id": e.get("id"), "affected": aff})

    prod_index = build_product_index(merged_products)
    prod_path = os.path.join(data_dir, "cve-products.json")
    _write_json(prod_path, prod_index)
    total_items = sum(len(v) for v in prod_index["map"].values())
    print(f"  영향 제품 인덱스: {len(prod_index['map']):,}건 · 항목 {total_items:,}개 "
          f"(고유 제품 {len(prod_index['products']):,}) → {prod_path}", flush=True)

    # 표에 그리는 몫만 남기고 자른다 (검색·상세는 위 인덱스를 쓴다)
    for e in cve_data:
        aff = e.get("affected") or []
        if len(aff) > TABLE_AFFECTED:
            e["affected"] = aff[:TABLE_AFFECTED]
            e["affected_total"] = len(aff)

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
