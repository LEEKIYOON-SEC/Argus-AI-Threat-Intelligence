"""
GitHub Pages 대시보드용 데이터 Export

Supabase에서 CVE 데이터를 조회하여
docs/data/*.json 정적 파일로 생성한다.
브라우저에서 직접 Supabase를 호출하지 않으므로 free tier 안전.
"""

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
from weekly_report import publish_weekly_report


def _get_client():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if not url or not key:
        return None
    return create_client(url, key)


def _s(state: dict, key: str, default: str = "") -> str:
    """JSONB에서 문자열 안전 추출.

    Supabase는 JSON의 null을 '키 있음 + 값 None'으로 돌려주므로 dict.get(k, default)의
    기본값이 발동하지 않는다. 그대로 쓰면 None.strip()/None[:n]에서 터지고, export는
    전량 일괄 처리라 단 한 행 때문에 대시보드 전체가 갱신되지 않는다."""
    v = state.get(key)
    return v if isinstance(v, str) else default


def _l(state: dict, key: str) -> list:
    """JSONB에서 리스트 안전 추출 (위와 동일한 이유)."""
    v = state.get(key)
    return v if isinstance(v, list) else []


def _write_json(path: str, payload) -> None:
    """임시 파일에 쓰고 원자적으로 바꿔치운다.

    바로 덮어쓰면 도중에 죽었을 때 잘린 JSON이 남는다. 데이터 파일을 더는 커밋하지
    않으므로 그 잘린 파일이 곧바로 배포돼 대시보드가 깨지고, 다음 실행이 그걸
    출발점으로 읽는다. os.replace는 같은 파일시스템에서 원자적이다."""
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def export_cves(client, days: int = 90, since: str = None) -> list:
    """최근 N일 CVE 데이터 export (페이지네이션으로 전체 로드).

    since를 주면 그 시각 이후 바뀐 행만 가져온다(증분). 매시간 90일치 전 행
    (~12,000행 × rules_snapshot·last_alert_state JSONB)을 통째로 읽으면 회당 ~15MB라
    월 10GB를 넘어 Supabase 무료 한도(5GB)를 초과했다 — 불변 원칙 2 위반이었다.
    """
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()

    rows = []
    page_size = 1000
    offset = 0
    while True:
        # last_alert_state가 null인 행은 마커(비자산 저위험 dedup용) — 대시보드 비노출
        query = client.table("cves") \
            .select("id, cvss_score, epss_score, is_kev, has_official_rules, last_alert_at, last_alert_state, rules_snapshot, report_url, updated_at") \
            .gte("updated_at", since or cutoff) \
            .not_.is_("last_alert_state", "null")
        response = query \
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

        # CWE는 'CWE-숫자' 형식만 통과 — 과거 수집분에 Oracle 등 cweId 없는 CNA의
        # 영향 설명 문장이 통째로 담긴 행이 있어(수집기는 수정됨) 표시 직전에 걸러낸다.
        # DB는 수동 관리 원칙이라 여기서 정리하면 기존 행도 재수집 없이 즉시 정상 표시.
        cwe_clean = []
        for w in _l(state, "cwe"):
            for m in re.findall(r"CWE-\d{1,4}\b", str(w)):
                if m not in cwe_clean:
                    cwe_clean.append(m)

        # 제목 폴백 — title 없는 CNA(Oracle 등)의 'N/A'가 '해당 없음'으로 번역·저장된
        # 기존 행을 affected 기반 제목으로 대체 (신규 수집분은 수집기에서 해결됨)
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
            "is_kev": row.get("is_kev", False),
            "cwe": cwe_clean,
            "affected": [],
            "report_url": row.get("report_url"),
            # Supabase는 null 컬럼도 키를 포함해 반환하므로 .get의 default가 발동하지 않음
            # → or 체인으로 폴백 (알림 없는 추적 CVE는 updated_at 사용)
            "date": row.get("last_alert_at") or row.get("updated_at") or "",
            # 증분 병합에서 보존 창(90일)을 판정하는 기준. 'date'로 대신하면 오래 전
            # 알림이 나간 뒤 최근에 재처리된 행이 창 밖으로 잘못 밀려 전량 export와
            # 결과가 갈린다. 화면에는 쓰지 않는다.
            "updated": row.get("updated_at") or "",
        }

        # affected 정보 간략화
        for aff in _l(state, "affected")[:3]:
            if not isinstance(aff, dict):
                continue
            entry["affected"].append({
                "vendor": _s(aff, "vendor", "Unknown"),
                "product": _s(aff, "product", "Unknown"),
                "versions": _s(aff, "versions"),
            })

        # 탐지 룰 정보 (네트워크 룰은 "network" 리스트에 저장되며 각 항목이 engine을 가짐)
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
        entry["has_official_rules"] = row.get("has_official_rules", False)
        entry["rules"] = rules

        # PoC 정보
        state_poc = state.get("has_poc", False)
        entry["has_poc"] = state_poc
        entry["poc_urls"] = _l(state, "poc_urls")[:3]

        # WAF 콘텐츠 차단으로 축소 저장된 행 — 모달에서 '원문은 리포트 참조' 안내에 사용
        entry["degraded"] = bool(state.get("waf_degraded"))
        # 공격 벡터 (모달 시각화용). 이 필드가 도입되기 전 행에는 없다 → 프론트에서 생략 처리
        entry["cvss_vector"] = _s(state, "cvss_vector")
        # 등록 자산(assets.json의 구체 룰)에 매칭된 CVE — '내 자산' 패널/필터용.
        # 판정은 파이프라인(is_target_asset)이 한 것을 그대로 쓴다(프론트 재구현 없음).
        entry["asset_match"] = state.get("match_type") == "asset"

        # P5 위협 신호 (vulnrichment SSVC / ExploitDB / Metasploit)
        entry["ssvc_exploitation"] = state.get("ssvc_exploitation") or (state.get("ssvc") or {}).get("exploitation")
        entry["has_public_exploit"] = state.get("has_public_exploit", False)
        entry["has_metasploit_module"] = state.get("has_metasploit_module", False)
        entry["metasploit_modules"] = _l(state, "metasploit_modules")[:3]

        # 자동화 악용 축 — CVSS(피해 크기)와 직교하는 '얼마나 쉽게 널리 자동화되는가'.
        # 값이 없는 행(도입 이전)은 프론트에서 딱지 자체를 생략한다.
        ssvc = state.get("ssvc") or {}
        entry["ssvc_automatable"] = state.get("ssvc_automatable") or ssvc.get("automatable")
        entry["ssvc_technical_impact"] = state.get("ssvc_technical_impact") or ssvc.get("technical_impact")
        entry["is_kev_ransomware"] = state.get("is_kev_ransomware", False)

        # CVE 공개일 — 추이 차트 전용. 'date'(우리가 확인한 날)와 다르다.
        entry["published"] = _s(state, "published")[:10]

        # Linux 커널 CVE 여부 — 커널 CNA가 커밋 단위로 할당해 목록의 절반을 차지하는데
        # 전부 Linux/Linux로만 표기돼 제품 단위 구분이 불가능하다. 목록에서 접어 묶는다.
        entry["is_kernel"] = any(
            _s(a, "vendor").strip().lower() == "linux" for a in entry["affected"]
        )

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


_FULL_EXPORT_MAX_AGE_H = 24


def _take_full_export_flag(client) -> bool:
    """백필이 남긴 '전량 export 요청' 표시를 읽고 지운다.

    백필은 '확인일'을 보존하려고 updated_at을 건드리지 않는데, 증분 export는 그 컬럼으로
    바뀐 행을 찾는다. 표시가 없으면 백필 결과가 대시보드에 영영 나타나지 않는다."""
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
    """지금 배포돼 있는 cves.json·stats.json. 못 받으면 (None, None).

    Pages는 공개 정적 파일이라 Supabase egress를 전혀 쓰지 않는다 — 증분의 출발점을
    DB가 아니라 사이트에서 가져오는 이유다."""
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
    """직전 export 결과와 그 시각. 증분의 출발점이 없으면 (None, None).

    (None, None)이면 호출부가 전량 export로 돌아간다 — 파일이 없거나 깨졌거나
    너무 오래됐을 때 스스로 복구되는 경로다."""
    if os.environ.get("ARGUS_FULL_EXPORT") == "1":
        print("  ARGUS_FULL_EXPORT=1 → 전량 export", flush=True)
        return None, None
    try:
        # 지금 서비스 중인 사이트를 먼저 본다. 데이터 파일을 더는 커밋하지 않으므로
        # 체크아웃에 남은 사본은 커밋을 멈춘 시점에 얼어붙은 옛날 것이고, 그걸
        # 출발점으로 삼으면 그 사이 변경이 통째로 빠진다. 받지 못하면(최초 배포 전,
        # 네트워크 차단) 체크아웃 사본으로 물러난다 — 오래됐으면 아래 24시간
        # 검사가 전량 export로 돌려놓는다.
        rows, generated_at = _fetch_live_export()
        if rows is None:
            with open(os.path.join(data_dir, "cves.json"), encoding="utf-8") as f:
                rows = json.load(f)
            with open(os.path.join(data_dir, "stats.json"), encoding="utf-8") as f:
                generated_at = json.load(f).get("generated_at")
        if not isinstance(rows, list) or not rows or not generated_at:
            return None, None
        # 직전 결과에 'updated'가 없으면 이 기능 도입 이전 파일 — 창 판정 기준이 없어
        # 병합하면 행이 잘못 빠진다. 한 번은 전량으로 돌려 기준을 채운다.
        if not any(r.get("updated") for r in rows[:50]):
            print("  직전 파일에 병합 기준(updated)이 없음 → 전량 export", flush=True)
            return None, None
        prev = dt.datetime.fromisoformat(str(generated_at).replace("Z", "+00:00"))
        age_h = (dt.datetime.now(dt.timezone.utc) - prev).total_seconds() / 3600
        if age_h > _FULL_EXPORT_MAX_AGE_H:
            print(f"  직전 export가 {age_h:.0f}시간 전 → 전량 export로 재동기화", flush=True)
            return None, None
        # 실행이 겹치거나 시계가 어긋나도 놓치지 않도록 10분 겹쳐서 가져온다
        return rows, (prev - dt.timedelta(minutes=10)).isoformat()
    except Exception as e:
        print(f"  직전 export를 읽지 못함({e}) → 전량 export", flush=True)
        return None, None


def merge_exports(previous: list, fresh: list, days: int = 90) -> list:
    """직전 결과에 이번에 바뀐 행을 덮어쓰고 보존 창을 다시 적용한다.

    DB에서 사라진 행(보존 정책의 삭제·JSONB null화)은 증분 조회로 알 수 없지만,
    그 처리는 전부 창(90일) 바깥에서만 일어나므로 여기서 창을 다시 적용하면 함께
    빠진다. 창 안쪽 행이 사라지는 경로는 없다."""
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    by_id = {r.get("id"): r for r in previous if r.get("id")}
    for r in fresh:
        if r.get("id"):
            by_id[r["id"]] = r
    merged = [r for r in by_id.values() if (r.get("updated") or "") >= cutoff]
    merged.sort(key=lambda r: r.get("updated") or "", reverse=True)
    return merged


def export_stats(cve_data: list) -> dict:
    """CVE 통계 집계"""
    now = dt.datetime.now(dt.timezone.utc)

    severity_counts = defaultdict(int)
    vendor_counts = defaultdict(int)
    product_counts = defaultdict(int)
    product_vendor = {}          # 제품 → 대표 벤더 (표시용 툴팁)
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

        # 일별 추이는 'CVE가 공개된 날' 기준. 확인일(date)로 세면 백로그를 몰아 처리한
        # 날에 수천 건이 몰려 실제 공개 추이를 왜곡한다(관측: 하루 2,545건 vs 실제 427건).
        # 공개일이 없는 행(도입 이전 저장분)은 추이에서 제외 — 확인일로 채우면 같은 왜곡이
        # 그대로 남는다. 백필이 끝나면 자연히 메워진다.
        pub = (cve.get("published") or "")[:10]
        if pub:
            daily_counts[pub] += 1

        # '최근 24시간'은 우리가 확인한 시각 기준이 맞다 — 파이프라인 처리량 지표이므로.
        date_str = cve.get("date", "")
        if date_str:
            try:
                cve_dt = dt.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if (now - cve_dt).total_seconds() < 86400:
                    recent_24h += 1
            except (ValueError, TypeError):
                pass

        # 커널 CVE는 제품 분포에서 뺀다 — 전부 Linux/Linux라 TOP을 통째로 독식하면서
        # '어떤 제품이 위험한가'는 하나도 알려주지 못한다. 건수는 따로 센다.
        if cve.get("is_kernel"):
            kernel_count += 1
            continue

        # 벤더/제품별 집계. 같은 CVE가 한 제품을 여러 번 나열해도 1건으로 센다
        # (버전 범위가 여러 개면 affected 항목이 중복되기 때문).
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

    # 일별 추이 — 오늘부터 거슬러 30일 창을 날짜로 고정하고 빈 날은 0으로 채운다.
    # 이전 구현(sorted(...)[-30:])은 '최근 30개 날짜'라서 최근 30일이 아니었다. 확인일
    # 기준일 땐 매일 데이터가 있어 우연히 맞아 보였지만, 공개일로 바꾸자 값이 드문드문
    # 있어 8개월치가 30칸에 들어갔다(관측: 2025-12-20 ~ 2026-08-14). 창을 날짜로 고정하면
    # 창 밖 과거와 미래 날짜(레코드 오류)가 함께 걸러진다.
    today = now.date()
    daily_trend = []
    for i in range(29, -1, -1):
        day = (today - dt.timedelta(days=i)).isoformat()
        daily_trend.append((day, daily_counts.get(day, 0)))

    # 공개일이 채워진 행 수. 백필이 끝나기 전에는 추이가 전체의 일부만 그리므로,
    # 대시보드가 "공개일 확인 N건 기준"이라고 밝힐 수 있게 함께 싣는다. 커버리지가
    # 100%가 되면 프런트에서 자연히 사라지는 안내다.
    trend_covered = sum(daily_counts.values())

    # 제품 TOP 10 — 실질 노출 파악의 기준. 벤더 기준은 재배포 벤더(Red Hat 등)가
    # 제품 수만큼 자동으로 상위를 차지해 '무엇이 위험한가'를 알려주지 못한다.
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


def apply_retention_policy(client, days: int = 120, marker_days: int = 30,
                           delete_days: int = 180, max_rows: int = 20000) -> int:
    """DB 용량 방어 (불변 원칙 2). 네 단계:

    1) 최근 days일 이전 레코드의 대용량 JSON 필드(rules_snapshot, last_alert_state)를 null 처리.
       상세 분석/룰 원문은 GitHub Issue에 영구 보존되므로 데이터 손실 없음.
       days는 대시보드 노출 창(export_cves의 90일)보다 30일 여유만 둔다 — 그 밖의
       last_alert_state는 어떤 소비자도 읽지 않아(에스컬레이션 스윕 30일, 룰 재확인은
       스칼라 컬럼만 사용) 순수 저장 비용이었다.
    2) marker_days일 지난 마커 행 삭제. 마커 = 비자산 저위험 dedup용(last_alert_state·
       last_alert_at 모두 null). 삭제해도 안전: 이후 레코드가 바뀌면 '신규'로 재분류되어
       고위험 승격 시 풀 알림이 나가고, KEV 등재는 gap-filler가 DB 유무와 무관하게 잡는다.
       (last_alert_at 조건으로 1)에서 null화된 과거 알림 행과는 구분 — 그 행들은 보존.)
    """
    cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)).isoformat()
    response = client.table("cves") \
        .update({"rules_snapshot": None, "last_alert_state": None}) \
        .lt("updated_at", cutoff) \
        .not_.is_("last_alert_state", "null") \
        .execute()
    cleaned = len(response.data or [])

    marker_cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=marker_days)).isoformat()
    deleted = client.table("cves") \
        .delete() \
        .is_("last_alert_state", "null") \
        .is_("last_alert_at", "null") \
        .lt("updated_at", marker_cutoff) \
        .execute()
    deleted_count = len(deleted.data or [])
    if deleted_count:
        print(f"  마커 {deleted_count}건 삭제 ({marker_days}일 경과)", flush=True)

    # 3) delete_days 지난 행은 완전 삭제. 지금까지는 JSONB만 비우고 행은 영구 누적이라
    #    수동 SQL로 정리하고 있었다. 안전한 이유: 조치 이력은 GitHub Issue에 남고
    #    (불변 원칙 2), 대시보드는 90일만 노출하며, KEV 재등재는 신호 드리프트 대조가
    #    등재일 기준으로 잡으므로 삭제된 행 때문에 재수집 루프가 생기지 않는다.
    row_cutoff = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=delete_days)).isoformat()
    purged = client.table("cves").delete().lt("updated_at", row_cutoff).execute()
    purged_count = len(purged.data or [])
    if purged_count:
        print(f"  오래된 행 {purged_count}건 삭제 ({delete_days}일 경과)", flush=True)

    # 4) 행 수 상한 — 유입이 폭주해도 DB가 무한정 커지지 않게 하는 안전판.
    #    오래된 것부터 초과분만 지운다.
    capped = 0
    total = _count(client)
    if total > max_rows:
        excess = total - max_rows
        victims = client.table("cves").select("id") \
            .order("updated_at", desc=False).limit(excess).execute()
        ids = [r["id"] for r in (victims.data or []) if r.get("id")]
        for i in range(0, len(ids), 200):
            client.table("cves").delete().in_("id", ids[i:i + 200]).execute()
            capped += len(ids[i:i + 200])
        print(f"  상한 초과 {capped}건 삭제 (상한 {max_rows:,}행)", flush=True)

    tracked = _count(client, tracked=True)
    remaining = _count(client)
    # '상태없음'은 마커(비자산 저위험 dedup용)와 보존정책이 JSONB를 비운 과거 행이
    # 섞인 수다. 둘을 나누려면 조회가 한 번 더 필요한데 그 값으로 할 일이 없다.
    print(f"  현황: 전체 {remaining:,} · 추적 {tracked:,} · 상태없음 {remaining - tracked:,} "
          f"(마커 + 보존정책이 비운 과거 행) · 이번 삭제 "
          f"{deleted_count + purged_count + capped:,}", flush=True)

    return cleaned


def _count(client, tracked: bool = False) -> int:
    """행 수만 센다(데이터 전송 없음). 실패해도 보존 정책을 멈추지 않는다."""
    try:
        q = client.table("cves").select("id", count="exact").limit(1)
        if tracked:
            q = q.not_.is_("last_alert_state", "null")
        return q.execute().count or 0
    except Exception as e:
        print(f"  [!] 행 수 조회 실패(무시): {e}", flush=True)
        return 0


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

    # CVE 데이터 — 직전 결과가 쓸 만하면 바뀐 행만 가져와 병합한다(증분).
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

    # 통계
    print("[2/4] 통계 집계...", flush=True)
    stats = export_stats(cve_data)
    stats_path = os.path.join(data_dir, "stats.json")
    _write_json(stats_path, stats)
    print(f"  Stats → {stats_path}", flush=True)

    # 주간 리포트 (직전 ISO 주가 아직 발행되지 않았을 때만)
    print("[3/4] 주간 리포트 확인...", flush=True)
    try:
        publish_weekly_report(cve_data)
    except Exception as e:
        print(f"  [!] 주간 리포트 생성 실패(무시): {e}", flush=True)

    # DB 보존 정책 (대용량 필드 정리 + 마커 삭제)
    print("[4/4] DB 보존 정책 적용...", flush=True)
    try:
        cleaned = apply_retention_policy(client)
        print(f"  {cleaned}건 정리 (rules_snapshot/last_alert_state null 처리)", flush=True)
    except Exception as e:
        print(f"  [!] DB 보존 정책 적용 실패: {e}", flush=True)

    print("=== Export 완료 ===", flush=True)


if __name__ == "__main__":
    main()
