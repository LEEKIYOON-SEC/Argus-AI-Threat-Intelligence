import os
import re
import json
import datetime
import threading
import time
import requests
import pytz
from concurrent.futures import ThreadPoolExecutor, as_completed, CancelledError
from typing import Dict, List, Tuple, Optional
from google import genai
from google.genai import types
from logger import logger
from config import config
from collector import (Collector, read_watermark, write_watermark,
                       read_failure_state, active_quarantine,
                       read_rpd_state, write_rpd_state)
from database import ArgusDB
from notifier import SlackNotifier
from analyzer import Analyzer
from rule_manager import RuleManager
from rate_limiter import rate_limit_manager, gemini_error_kind, gemini_backoff

# KST 타임존 (한국 표준시)
KST = pytz.timezone('Asia/Seoul')

# Gemini 클라이언트 (한국어 번역용). HTTP 타임아웃 120초 — 응답이 행에 걸려
# 파이프라인 전체(시간 예산)를 잡아먹는 것을 방지. 실패는 영문 폴백이 흡수.
try:
    gemini_client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
        http_options=types.HttpOptions(timeout=120_000),
    )
except Exception:  # 구버전 SDK 등 http_options 미지원 시
    gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# ==============================================================================
# [1] CVSS 벡터 해석 매핑
# ==============================================================================
CVSS_MAP = {
    # ==========================================
    # [CVSS 3.1 Base Metrics]
    # ==========================================
    "AV:N": "공격 경로: 네트워크 (Network)", "AV:A": "공격 경로: 인접 (Adjacent)", "AV:L": "공격 경로: 로컬 (Local)", "AV:P": "공격 경로: 물리적 (Physical)",
    "AC:L": "복잡성: 낮음", "AC:H": "복잡성: 높음",
    "PR:N": "필요 권한: 없음", "PR:L": "필요 권한: 낮음", "PR:H": "필요 권한: 높음",
    "UI:N": "사용자 관여: 없음", "UI:R": "사용자 관여: 필수",
    "S:U": "범위: 변경 없음", "S:C": "범위: 변경됨 (Changed)",
    "C:H": "기밀성: 높음", "C:L": "기밀성: 낮음", "C:N": "기밀성: 없음",
    "I:H": "무결성: 높음", "I:L": "무결성: 낮음", "I:N": "무결성: 없음",
    "A:H": "가용성: 높음", "A:L": "가용성: 낮음", "A:N": "가용성: 없음",

    # ==========================================
    # [CVSS 3.1 Temporal / Threat Metrics]
    # ==========================================
    "E:X": "악용 가능성: 미정의", "E:U": "악용 가능성: 입증 안됨", "E:P": "악용 가능성: 개념 증명(PoC)", "E:F": "악용 가능성: 기능적", "E:H": "악용 가능성: 높음",
    "RL:X": "대응 수준: 미정의", "RL:O": "대응 수준: 공식 패치", "RL:T": "대응 수준: 임시 수정", "RL:W": "대응 수준: 우회 가능", "RL:U": "대응 수준: 사용 불가",
    "RC:X": "보고 신뢰도: 미정의", "RC:U": "보고 신뢰도: 미확인", "RC:R": "보고 신뢰도: 합리적", "RC:C": "보고 신뢰도: 확인됨",

    # ==========================================
    # [CVSS 3.1 Environmental Metrics]
    # ==========================================
    "MAV:N": "수정된 경로: 네트워크", "MAV:A": "수정된 경로: 인접", "MAV:L": "수정된 경로: 로컬", "MAV:P": "수정된 경로: 물리적",
    "MAC:L": "수정된 복잡성: 낮음", "MAC:H": "수정된 복잡성: 높음",
    "MPR:N": "수정된 권한: 없음", "MPR:L": "수정된 권한: 낮음", "MPR:H": "수정된 권한: 높음",
    "MUI:N": "수정된 관여: 없음", "MUI:R": "수정된 관여: 필수",
    "MS:U": "수정된 범위: 변경 없음", "MS:C": "수정된 범위: 변경됨",
    "MC:H": "수정된 기밀성: 높음", "MC:L": "수정된 기밀성: 낮음", "MC:N": "수정된 기밀성: 없음",
    "MI:H": "수정된 무결성: 높음", "MI:L": "수정된 무결성: 낮음", "MI:N": "수정된 무결성: 없음",
    "MA:H": "수정된 가용성: 높음", "MA:L": "수정된 가용성: 낮음", "MA:N": "수정된 가용성: 없음",
    "CR:X": "기밀성 요구: 미정의", "CR:L": "기밀성 요구: 낮음", "CR:M": "기밀성 요구: 보통", "CR:H": "기밀성 요구: 높음",
    "IR:X": "무결성 요구: 미정의", "IR:L": "무결성 요구: 낮음", "IR:M": "무결성 요구: 보통", "IR:H": "무결성 요구: 높음",
    "AR:X": "가용성 요구: 미정의", "AR:L": "가용성 요구: 낮음", "AR:M": "가용성 요구: 보통", "AR:H": "가용성 요구: 높음",

    # ==========================================
    # [CVSS 4.0 Base Metrics]
    # ==========================================
    "AT:N": "공격 기술: 없음", "AT:P": "공격 기술: 존재(Present)",
    "VC:H": "취약시스템 기밀성: 높음", "VC:L": "취약시스템 기밀성: 낮음", "VC:N": "취약시스템 기밀성: 없음",
    "VI:H": "취약시스템 무결성: 높음", "VI:L": "취약시스템 무결성: 낮음", "VI:N": "취약시스템 무결성: 없음",
    "VA:H": "취약시스템 가용성: 높음", "VA:L": "취약시스템 가용성: 낮음", "VA:N": "취약시스템 가용성: 없음",
    "SC:H": "후속시스템 기밀성: 높음", "SC:L": "후속시스템 기밀성: 낮음", "SC:N": "후속시스템 기밀성: 없음",
    "SI:H": "후속시스템 무결성: 높음", "SI:L": "후속시스템 무결성: 낮음", "SI:N": "후속시스템 무결성: 없음",
    "SA:H": "후속시스템 가용성: 높음", "SA:L": "후속시스템 가용성: 낮음", "SA:N": "후속시스템 가용성: 없음",

    # ==========================================
    # [CVSS 4.0 Environmental (Modified Base) Metrics]
    # ==========================================
    "MAT:N": "수정된 공격 기술: 없음", "MAT:P": "수정된 공격 기술: 존재",
    "MVC:H": "수정된 취약시스템 기밀성: 높음", "MVC:L": "수정된 취약시스템 기밀성: 낮음", "MVC:N": "수정된 취약시스템 기밀성: 없음",
    "MVI:H": "수정된 취약시스템 무결성: 높음", "MVI:L": "수정된 취약시스템 무결성: 낮음", "MVI:N": "수정된 취약시스템 무결성: 없음",
    "MVA:H": "수정된 취약시스템 가용성: 높음", "MVA:L": "수정된 취약시스템 가용성: 낮음", "MVA:N": "수정된 취약시스템 가용성: 없음",
    "MSC:H": "수정된 후속시스템 기밀성: 높음", "MSC:L": "수정된 후속시스템 기밀성: 낮음", "MSC:N": "수정된 후속시스템 기밀성: 없음", "MSC:S": "수정된 후속시스템 기밀성: 안전(Safety)",
    "MSI:H": "수정된 후속시스템 무결성: 높음", "MSI:L": "수정된 후속시스템 무결성: 낮음", "MSI:N": "수정된 후속시스템 무결성: 없음", "MSI:S": "수정된 후속시스템 무결성: 안전(Safety)",
    "MSA:H": "수정된 후속시스템 가용성: 높음", "MSA:L": "수정된 후속시스템 가용성: 낮음", "MSA:N": "수정된 후속시스템 가용성: 없음", "MSA:S": "수정된 후속시스템 가용성: 안전(Safety)",

    # ==========================================
    # [CVSS 4.0 Supplemental Metrics]
    # ==========================================
    "S:X": "안전(Safety): 미정의", "S:N": "안전(Safety): 무시 가능", "S:P": "안전(Safety): 존재(Present)",
    "AU:X": "자동화 가능성: 미정의", "AU:N": "자동화 가능성: 아니오", "AU:Y": "자동화 가능성: 예",
    "R:X": "복구(Recovery): 미정의", "R:A": "복구: 자동", "R:U": "복구: 사용자", "R:I": "복구: 복구 불가",
    "V:X": "가치 밀도: 미정의", "V:D": "가치 밀도: 분산(Diffuse)", "V:C": "가치 밀도: 집중(Concentrated)",
    "RE:X": "대응 노력: 미정의", "RE:L": "대응 노력: 낮음", "RE:M": "대응 노력: 보통", "RE:H": "대응 노력: 높음",
    "U:X": "긴급성: 미정의", "U:Clear": "긴급성: 명확함", "U:Green": "긴급성: 낮음(Green)", "U:Amber": "긴급성: 주의(Amber)", "U:Red": "긴급성: 높음(Red)"
}

# ==============================================================================
# [2] 유틸리티 함수들
# ==============================================================================

def parse_cvss_vector(vector_str: str) -> str:
    if not vector_str or vector_str == "N/A":
        return "정보 없음"
    
    parts = vector_str.split('/')
    mapped_parts = []
    
    for part in parts:
        if ':' in part:
            full_key = part
            desc = CVSS_MAP.get(full_key, f"**{part}**")
            if full_key in CVSS_MAP:
                mapped_parts.append(f"• {desc}")
            else:
                mapped_parts.append(f"• {part}")
    
    return "<br>".join(mapped_parts)

def is_target_asset(cve_data: Dict) -> Tuple[bool, Optional[str], Optional[str]]:
    """자산 매칭 판정. 반환: (매칭 여부, 매칭 근거, 매칭 종류).

    매칭 종류(match_type)가 자산 기준 티어링의 핵심이다:
      "asset"    — 등록된 구체 자산 룰에 매칭 → 저위험도 추적(번역+대시보드)
      "wildcard" — 구체 룰엔 안 맞고 */*(전체 감시)로만 매칭 → 고위험/에스컬레이션만 수신,
                   신규 저위험은 마커만 저장(대시보드 비노출)
      None       — 어느 룰에도 안 맞음 → 처리 안 함
    구체 룰을 전부 먼저 검사하고, 실패했을 때만 wildcard로 분류한다."""
    # 벤더/제품 표기 차이(언더스코어 vs 공백)를 흡수해 매칭 누락 방지.
    # None 허용 — 레코드/DB 상태에 null이 섞여도 매칭이 죽지 않아야 한다.
    def _norm(s) -> str:
        return str(s or '').lower().replace('_', ' ').strip()

    has_wildcard = False
    for target in config.get_target_assets():
        t_vendor = _norm(target.get('vendor', ''))
        t_product = _norm(target.get('product', ''))

        # 전체 감시 룰은 기억만 하고 구체 룰부터 검사 (asset 판정이 우선)
        if t_vendor == "*" and t_product == "*":
            has_wildcard = True
            continue

        # 벤더 무관 룰(*/product)은 벤더가 비어 있어도 제품만으로 판정해야 한다 —
        # 애초에 '벤더를 모를 때' 쓰라고 있는 표기이므로, 벤더 불명을 이유로 건너뛰면
        # 그 기능이 가장 필요한 케이스에서만 매칭이 실패한다.
        vendor_agnostic = (t_vendor == "*")

        # 1차: affected 필드의 구조화된 vendor/product 매칭
        for affected in cve_data.get('affected') or []:
            a_vendor = _norm(affected.get('vendor'))
            a_product = _norm(affected.get('product'))

            unknown_vendor = a_vendor in ('', 'unknown', 'n/a')
            # 벤더가 필요한 룰인데 벤더가 불명 → 이 항목으로는 판정 불가 (2·3차에서 확인)
            if unknown_vendor and not vendor_agnostic:
                continue
            # 벤더 무관 룰인데 제품마저 불명 → 판정 근거 없음
            if vendor_agnostic and a_product in ('', 'unknown', 'n/a'):
                continue

            vendor_match = vendor_agnostic or (t_vendor in a_vendor) or (a_vendor in t_vendor)
            product_match = (t_product == "*") or (t_product in a_product) or (a_product in t_product)

            if vendor_match and product_match:
                return True, f"Matched (affected): {a_vendor or '*'}/{a_product}", "asset"

        # 2차: NVD CPE의 vendor/product 매칭 (affected가 비거나 불명일 때 보완)
        for cpe in cve_data.get('nvd_cpe') or []:
            parts = str(cpe).split(':')
            if len(parts) < 5:
                continue
            c_vendor, c_product = _norm(parts[3]), _norm(parts[4])
            unknown_vendor = c_vendor in ('', '*', '-')
            if unknown_vendor and not vendor_agnostic:
                continue
            if vendor_agnostic and c_product in ('', '*', '-'):
                continue
            vendor_match = vendor_agnostic or (t_vendor in c_vendor) or (c_vendor in t_vendor)
            product_match = (t_product == "*") or (t_product in c_product) or (c_product in t_product)
            if vendor_match and product_match:
                return True, f"Matched (NVD CPE): {c_vendor or '*'}/{c_product}", "asset"

        # 3차(보조): description 텍스트 매칭
        desc_lower = str(cve_data.get('description') or '').lower()
        if desc_lower and t_vendor in desc_lower and (t_product == "*" or t_product in desc_lower):
            return True, f"Matched (description): {t_vendor}/{t_product}", "asset"

    if has_wildcard:
        return True, "All Assets (*)", "wildcard"
    return False, None, None

def _log_deferred_severity_estimate(deferred: List[Dict], collector: Collector,
                                    deadline_ts: float) -> None:
    """이월(백로그) 대기열의 심각도 분포를 표본 추출로 추정해 로그로 남긴다 (관측 전용).

    이월분은 레코드를 아직 받지 않아 정확한 분류가 불가 — 표본 N건만 raw JSON
    (peek_cvss, API 한도 미소모)으로 레코드 CVSS(CNA→CISA-ADP)를 읽어 전체로 외삽한다.
    실제 처리 시의 티어(KEV/EPSS/Metasploit/SSVC 신호 반영)와는 다를 수 있는 참고 추정치.
    KEV 해당 건수는 메모리 세트 조회라 전수 집계. 실패 시 조용히 생략 — 파이프라인 무영향.
    """
    sample_n = config.PERFORMANCE.get("deferred_severity_sample", 80)
    if sample_n <= 0 or not deferred:
        return
    if time.time() > deadline_ts - 120:  # 시간 예산 임박 → 관측은 생략하고 본 처리에 양보
        return
    try:
        ids = [c['cve_id'] for c in deferred]
        kev_cnt = sum(1 for i in ids if i in collector.kev_set)
        # 균등 간격 표본 — 커밋시각 순 정렬이므로 기간 전체를 고르게 커버한다
        step = max(1, len(ids) // sample_n)
        sample = ids[::step][:sample_n]
        buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
        with ThreadPoolExecutor(max_workers=config.PERFORMANCE["max_workers"]) as ex:
            for score in ex.map(collector.peek_cvss, sample):
                if not score:
                    buckets["unknown"] += 1
                elif score >= 9.0:
                    buckets["critical"] += 1
                elif score >= 7.0:
                    buckets["high"] += 1
                elif score >= 4.0:
                    buckets["medium"] += 1
                else:
                    buckets["low"] += 1
        n, total = len(sample), len(ids)

        def fmt(key: str) -> str:
            return f"~{round(total * buckets[key] / n)}건({buckets[key] / n * 100:.0f}%)"

        kev_note = f" · KEV {kev_cnt}건(전수)" if kev_cnt else ""
        logger.info(
            f"📊 이월 {total}건 심각도 추정(표본 {n}건, 레코드 CVSS 기준): "
            f"Critical {fmt('critical')} / High {fmt('high')} / Medium {fmt('medium')} / "
            f"Low {fmt('low')} / 점수미상 {fmt('unknown')}{kev_note}"
        )
    except Exception as e:
        logger.debug(f"이월 심각도 추정 생략: {e}")


def _looks_english(text: str) -> bool:
    """한글이 한 글자도 없는 (=번역 안 된) 텍스트인지. 짧은 제품명 등 오탐 방지로 길이 하한."""
    t = (text or '').strip()
    return len(t) > 25 and not re.search(r'[가-힣]', t)


def backfill_translations(db: ArgusDB, deadline_ts: float) -> None:
    """영문으로 남은 추적 CVE의 제목·설명을 재번역 (대시보드 품질 백필).

    Phase B가 시간 예산에 걸리면 그 회차 CVE는 영문 폴백으로 저장되고, 레코드가 다시
    바뀌지 않는 한 영영 영문으로 남는다(대시보드 절반이 영문이 되는 원인). 매 실행
    소량씩 재번역해 점진적으로 해소한다. 시간·건수 상한이 있어 본 파이프라인을 침범하지 않는다.
    """
    limit = config.PERFORMANCE.get("translation_backfill_per_run", 0)
    if limit <= 0:
        return
    # 본 처리를 마친 뒤 남는 시간에만 — 예산이 빠듯하면 통째로 생략
    reserve = config.PERFORMANCE.get("phase_c_reserve_minutes", 8) * 60
    if time.time() > deadline_ts - reserve:
        logger.info("번역 백필 생략 (시간 예산 부족)")
        return
    try:
        pool = config.PERFORMANCE.get("translation_backfill_pool", 200)
        candidates = db.get_translation_backfill_candidates(limit=pool)
        items = []
        for row in candidates:
            state = row.get('last_alert_state') or {}
            title_ko = state.get('title_ko') or state.get('title') or ''
            if not _looks_english(title_ko):
                continue
            items.append({"id": row['id'],
                          "title": state.get('title') or title_ko,
                          "description": state.get('description') or state.get('desc_ko') or ''})
            if len(items) >= limit:
                break
        if not items:
            logger.info("번역 백필: 대상 없음 (최근 추적분 모두 한글화됨)")
            return

        logger.info(f"🈯 번역 백필: 영문 잔존 {len(items)}건 재번역 시도")
        translations = generate_korean_summaries_batch(items, set(), deadline_ts=deadline_ts)
        fixed = 0
        for it in items:
            tr = translations.get(it['id'])
            # 번역이 여전히 영문이면(폴백) 저장하지 않는다 — 무의미한 DB 쓰기 방지
            if not tr or _looks_english(tr[0]):
                continue
            if db.update_translation(it['id'], tr[0], tr[1]):
                fixed += 1
        logger.info(f"🈯 번역 백필 완료: {fixed}/{len(items)}건 한글화")
    except Exception as e:
        logger.warning(f"번역 백필 생략(오류): {e}")


def _iso_after(ts: str, cutoff: datetime.datetime) -> bool:
    """ISO 시각 문자열이 cutoff 이후인지 (파싱 실패 시 True — 임의 삭제 방지)."""
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")) >= cutoff
    except ValueError:
        return True


def _kev_drift_candidates(collector: Collector, db: ArgusDB, exclude: set,
                          new_days: int = 14) -> List[str]:
    """CISA KEV 목록을 DB와 대조해 아직 KEV로 반영되지 않은 CVE를 찾는다.

    두 종류를 다르게 취급한다.
      ① 플래그 미반영 — DB에 있는데 is_kev=false. 우리가 이미 추적 중인 CVE가 나중에
         KEV에 오른 경우로, **등재일과 무관하게 전량** 잡는다. 예전에는 이걸 아무도
         못 봤다: 레코드 무변경이라 재수집이 안 되고, 에스컬레이션 스윕은 CVSS<7만 봤고,
         gap-filler는 '존재 여부'만 봐서 마커 행(last_alert_state=null)까지 건너뛰었다.
      ② DB 미보유 — 최근 N일 등재분만 잡는다(기존 gap-filler 취지). 기간 제한이 필요한
         이유는 보존정책이 오래된 행을 지우기 때문이다. 전량을 잡으면 '수집 → 저장 →
         보존정책 삭제 → 재수집'이 매 실행 반복된다.

    비용: 스칼라 2개(id, is_kev)만 조회하므로 전량(1,600여 건) 대조도 수십 KB에 그친다."""
    kev_ids = [cid for cid in collector.kev_set if cid not in exclude]
    if not kev_ids:
        return []
    flags = db.batch_get_scalar(kev_ids, "is_kev")   # DB 미보유 id는 결과에 없음

    stale = [cid for cid in kev_ids if cid in flags and not flags[cid]]

    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=new_days)).strftime('%Y-%m-%d')
    missing = [cid for cid in kev_ids
               if cid not in flags and (collector.kev_date_added.get(cid) or '') >= cutoff]

    drifted = stale + missing
    if drifted:
        logger.info(f"🚨 KEV 드리프트 {len(drifted)}건 "
                    f"(플래그 미반영 {len(stale)} · 최근 {new_days}일 미보유 {len(missing)}) "
                    f"— KEV 전량 {len(kev_ids)}건 대조")
    return drifted


def _epss_surge_candidates(collector: Collector, db: ArgusDB, exclude: set,
                           threshold: float = 0.1) -> List[str]:
    """EPSS 전량 덤프에서 임계 이상인 CVE 중, DB에 저장된 점수가 아직 임계 미만인 것.

    KEV와 같은 이유로 방향을 뒤집는다. 다만 임계 이상이 1~2만 건이라 전량 대조는
    대역폭이 아까우므로, 직전 실행의 임계 이상 집합과 비교해 '새로 넘어선 것'만 본다.
    스냅샷이 없으면(최초 실행·캐시 유실) 이번 회차는 건너뛴다 — 다음 회차부터 델타가
    생기고, 그 사이 구간은 기존 에스컬레이션 스윕이 계속 커버한다."""
    from enrichment_sources import cache_get, cache_put

    high = collector.fetch_epss_high(threshold)
    if not high:
        return []

    prev_raw = cache_get("epss-high-prev.json", ttl_hours=72)
    try:
        prev = set(json.loads(prev_raw.decode())) if prev_raw else None
    except (ValueError, AttributeError):
        prev = None

    cache_put("epss-high-prev.json", json.dumps(sorted(high)).encode())
    if prev is None:
        logger.info("EPSS 임계 스냅샷 최초 기록 — 이번 회차 델타 판정은 건너뜀")
        return []

    surged = [cid for cid in high if cid not in prev and cid not in exclude]
    if not surged:
        return []
    stored = db.batch_get_scalar(surged, "epss_score")
    drifted = [cid for cid in surged
               if cid in stored and (stored.get(cid) or 0.0) < threshold]
    if drifted:
        logger.info(f"📈 EPSS 임계 신규 돌파 {len(surged)}건 중 DB 미반영 {len(drifted)}건")
    return drifted


def _needs_cpe_lookup(cve_data: Dict) -> bool:
    """NVD CPE 선제 조회가 필요한지 — CVE에 유효한 벤더가 하나도 없으면 True.

    조회 이유가 둘이다:
      1) 자산 매칭 — 특정 자산 감시(*/* 아님)면 벤더 없이는 매칭 자체가 불가능해
         감시 대상 CVE를 놓친다.
      2) 표시·필터 — 전체 감시(*/*)라도 벤더가 비면 대시보드 벤더 필터에서 통째로
         빠지고 리포트의 '영향 받는 자산'이 n/a로 남는다.

    예전에는 1)만 보고 전체 감시에서 건너뛰었다. 매칭 관점에선 맞지만 그 부작용으로
    표시용 벤더까지 같이 잃어, 추적 CVE의 1.6%(실측 198건)가 벤더 없이 남았다.
    원본 CNA 레코드가 'n/a'여도 NVD CPE에는 있는 경우가 있다
    (예: CVE-2020-29574 → cpe:2.3:o:sophos:cyberoamos).

    비용은 벤더 없는 CVE에 대해서만 NVD 1회다(실측 유입의 1.6%)."""
    return not any(
        str(a.get('vendor') or '').lower() not in ('', 'unknown', 'n/a')
        for a in (cve_data.get('affected') or [])
    )

def generate_korean_summary(cve_data: Dict, retry_on_transient: bool = False) -> Tuple[str, str]:
    """CVE 제목/설명을 한국어로 번역. 실패 시 영문 원본 폴백.

    retry_on_transient: 고위험/에스컬레이션 CVE는 True로 호출 → 무료 Gemma의 일시
        서버 오류(503 high demand / 500 INTERNAL)에 대해 백오프 재시도로 한글화를
        보장한다. 저위험(False)은 재시도 없이 오류 시 즉시 영문 폴백(중요도 낮음 +
        Gemma 부하 억제). 어느 경우든 비일시 오류(안전차단·400·429)는 즉시 폴백.
    """
    prompt = f"""
Task: Translate Title and Summarize Description into Korean.
[Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
[Format]
제목: [Korean Title]
내용: [Korean Summary (Max 3 lines)]
Do NOT add intro/outro.
"""

    fallback = (cve_data['title'], cve_data['description'][:200])

    # 무료 Gemma는 과부하 시 503(high demand)/500(INTERNAL) 같은 일시 서버 오류를 낸다.
    # 이는 우리 한도(429)가 아니라 구글 서버측 문제. 고위험만 백오프 재시도로 회복하고
    # 저위험은 즉시 폴백. 그 외(안전 차단·잘못된 요청 등)는 재시도해도 무의미.
    max_attempts = 3 if retry_on_transient else 1
    for attempt in range(1, max_attempts + 1):
        try:
            if not rate_limit_manager.check_and_wait("gemini"):
                # 일일 한도 소진 — 호출해봐야 429만 받는다
                _tr_bump("en_rpd")
                return fallback
            response = gemini_client.models.generate_content(
                model=config.MODEL_PHASE_0,
                contents=prompt,
                config=types.GenerateContentConfig(
                    # 번역은 짧음(제목 + 3줄). 출력 상한을 두지 않으면 gemma-4가
                    # 폭주 생성 → 서버 타임아웃(500 INTERNAL)을 유발한다.
                    max_output_tokens=1024,
                    temperature=0.3,
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )]
                )
            )
            # Gemini 토큰 사용량 기록 (프리티어 잔여량 가시화)
            gemini_tokens = 0
            usage = getattr(response, "usage_metadata", None)
            if usage is not None:
                gemini_tokens = getattr(usage, "total_token_count", 0) or 0
            rate_limit_manager.record_call("gemini", tokens_used=gemini_tokens)

            text = response.text.strip()
            title_ko, desc_ko = cve_data['title'], cve_data['description'][:200]

            for line in text.split('\n'):
                if line.startswith("제목:"):
                    title_ko = line.replace("제목:", "").strip()
                if line.startswith("내용:"):
                    desc_ko = line.replace("내용:", "").strip()

            _tr_bump("ok")
            return title_ko, desc_ko

        except Exception as e:
            msg = str(e)
            kind = _gemini_error_kind(msg)
            if kind == "rpd":
                # 공급자가 먼저 일일 소진을 알려줬다 = 우리 카운터가 실제보다 적게 셌다는 뜻.
                # 소진으로 마킹해 이번 실행의 남은 번역이 429를 반복하지 않게 한다.
                rate_limit_manager.mark_rpd_exhausted("gemini")
                logger.warning("번역 일일 한도(RPD) 소진 — 이후 번역은 영문 폴백")
                _tr_bump("en_rpd")
                return fallback
            if kind in ("rate", "transient") and attempt < max_attempts:
                wait = _gemini_backoff(kind, attempt, msg)
                logger.warning(f"번역 {kind} 오류({attempt}/{max_attempts}): {e} → {wait:.0f}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"번역 실패({kind}): {e}, 원본 사용")
            _tr_bump(f"en_{kind}")
            return fallback

    return fallback


# 대기 규칙도 rate_limiter가 소유한다 — 분류(gemini_error_kind)와 같은 자리에 둬야
# 번역과 분석이 서로 다른 규칙으로 기다리는 일이 생기지 않는다.
_gemini_backoff = gemini_backoff


# 오류 분류는 rate_limiter가 소유한다 — 분석 경로(analyzer)와 같은 기준을 써야
# 분당 한도를 일일 소진으로 오판해 하루치를 버리는 일이 한쪽에서만 생기지 않는다.
_gemini_error_kind = gemini_error_kind


# 번역 결과 집계 — 왜 영문이 남았는지(일일한도/분당한도/서버오류/형식오류)를 실행 로그
# 한 줄로 남긴다. 원인별 건수가 없으면 "가끔 503이 난다" 이상으로 진단할 수 없다.
_TR_LOCK = threading.Lock()
_TR_STATS: Dict[str, int] = {}
_TR_LABELS = [("en_rpd", "일일한도"), ("en_rate", "분당한도"), ("en_transient", "서버오류"),
              ("en_parse", "형식오류"), ("en_deadline", "시간초과"), ("en_other", "기타")]
# _translate_chunk가 돌려준 사유 → 집계 키
_TR_REASON_KEY = {"skip": "en_rpd", "rate": "en_rate", "transient": "en_transient",
                  "parse": "en_parse", "other": "en_other", "api": "en_other"}


def _tr_bump(key: str, n: int = 1) -> None:
    if n <= 0:
        return
    with _TR_LOCK:
        _TR_STATS[key] = _TR_STATS.get(key, 0) + n


def _log_translation_summary() -> None:
    """실행 누적 번역 결과 한 줄 요약 (배치 호출 종료 시점마다 갱신 출력)."""
    with _TR_LOCK:
        snap = dict(_TR_STATS)
    ok = snap.get("ok", 0)
    fallback = sum(snap.get(k, 0) for k, _ in _TR_LABELS)
    if not (ok or fallback):
        return
    breakdown = " · ".join(f"{label} {snap.get(key, 0)}" for key, label in _TR_LABELS)
    used, limit = rate_limit_manager.rpd_status("gemini")
    logger.info(f"🈯 번역 요약(누적): 한글 {ok}건 · 영문폴백 {fallback}건 "
                f"({breakdown}) · Gemma RPD {used:,}/{limit:,}")


def generate_korean_summaries_batch(items: List[Dict], high_risk_ids: set,
                                    deadline_ts: Optional[float] = None) -> Dict[str, Tuple[str, str]]:
    """대시보드/알림에 노출되는 CVE(마커 제외)의 제목·설명을 한국어로 번역.

    빠른 경로(배치): Gemma 1콜에 여러 건을 JSON 배열로 요청 — 성공 시 호출 수↓.
    견고 경로(폴백): 배치가 JSON 형식을 못 지키면(gemma-4는 배치 JSON을 자주 깨뜨림)
      그 청크를 '제목:/내용:' 텍스트 형식의 개별 번역으로 재처리 — 파싱이 견고해 한글을
      보장한다. 최후에만 영문 폴백. 시간 예산 초과 시 잔여는 영문(알림 대상만 개별 재시도).

    티어링으로 번역 대상이 (알림+High추적+자산저위험)뿐이라 개별 폴백도 시간 예산 내
    완주한다. 반환: cve_id → (title_ko, desc_ko). 모든 입력 id에 값이 존재한다.
    """
    results: Dict[str, Tuple[str, str]] = {}
    if not items:
        return results

    # 알림 대상(Critical/자산High)을 앞 청크로 — 시간 예산에 걸려 잔여가 영문 폴백되더라도
    # Issue/Slack에 나가는 핵심 건은 항상 한국어 번역을 확보한다.
    items = sorted(items, key=lambda it: 0 if it['id'] in high_risk_ids else 1)

    batch_size = config.PERFORMANCE.get("translation_batch_size", 6)
    chunks = [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
    total_chunks = len(chunks)
    # 병목은 한도가 아니라 '콜 1건의 생성 지연 × 직렬 처리'다 — gemma-4 무료 서빙이
    # 청크(6건 JSON) 하나에 ~55초. 직렬이면 66청크 ≈ 60분인데 RPM은 15 중 ~1.1만 쓴다.
    # → 청크를 동시 4콜로: RPM ~4.4/15·TPM ~12K/250K로 여전히 여유, 벽시계 시간 ~1/4.
    concurrency = max(1, config.PERFORMANCE.get("translation_concurrency", 4))
    logger.info(f"번역: {len(items)}건 → Gemma 배치 {total_chunks}청크 "
                f"(배치 {batch_size}건, 동시 {concurrency}콜)")
    started = time.time()
    lock = threading.Lock()
    state = {"done": 0, "deadline_warned": False, "fell_back": 0}

    def _individual(it: Dict, allow_retry: bool) -> Tuple[str, str]:
        return generate_korean_summary(
            {"title": it['title'], "description": it['description']},
            retry_on_transient=allow_retry)

    def _do_chunk(chunk: List[Dict]) -> Dict[str, Tuple[str, str]]:
        out: Dict[str, Tuple[str, str]] = {}
        # 데드라인 검사는 호출 직전(워커 안) — 큐에 밀려 있던 잔여 청크가 즉시 영문 폴백
        if deadline_ts is not None and time.time() > deadline_ts:
            with lock:
                if not state["deadline_warned"]:
                    logger.warning(f"⏰ 번역 시간 예산 도달 — 잔여 ~{total_chunks - state['done']}청크 영문 폴백")
                    state["deadline_warned"] = True
            for it in chunk:
                out[it['id']] = (it['title'], (it['description'] or '')[:200])
            _tr_bump("en_deadline", len(chunk))
            return out
        try:
            # 배치 시도 — 호출 수가 적으므로 항상 일시오류 재시도 허용
            parsed, reason = _translate_chunk(chunk, retry_on_transient=True)
            if parsed is not None:
                out.update(parsed)
                _tr_bump("ok", len(chunk))
            elif reason == "parse":
                # 응답 형식만 깨진 경우 → 개별 텍스트 번역으로 폴백(한글 보장). 이 CVE들은
                # 대시보드에 노출되므로 영문 방치보다 개별 번역 비용이 낫다.
                # (개별 호출의 성공/실패 집계는 generate_korean_summary가 직접 기록한다.)
                with lock:
                    state["fell_back"] += len(chunk)
                for it in chunk:
                    out[it['id']] = _individual(it, allow_retry=True)
            else:
                # API 자체가 실패(429/503/한도 소진) → 개별 재시도는 같은 오류를 6배로
                # 늘릴 뿐이다. 영문으로 두고 다음 실행의 번역 백필이 회수한다.
                for it in chunk:
                    out[it['id']] = (it['title'], (it['description'] or '')[:200])
                _tr_bump(_TR_REASON_KEY.get(reason, "en_other"), len(chunk))
        except Exception as e:
            logger.warning(f"번역 청크 실패 → 영문 폴백: {e}")
            for it in chunk:
                out.setdefault(it['id'], (it['title'], (it['description'] or '')[:200]))
            _tr_bump("en_other", len(chunk))
        with lock:
            state["done"] += 1
            done = state["done"]
        if done % 5 == 0 or done == total_chunks:
            logger.info(f"번역 진행: {done}/{total_chunks} 청크 ({time.time() - started:.0f}초)")
        return out

    # 제출 순서 = 정렬 순서(알림 대상 먼저) → 워커 큐도 FIFO라 핵심 건이 먼저 번역된다
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        for out in ex.map(_do_chunk, chunks):
            results.update(out)

    if state["fell_back"]:
        logger.info(f"번역: 배치 응답 형식 파손 {state['fell_back']}건 → 개별 번역으로 재시도")
    _log_translation_summary()
    return results


def _translate_chunk(chunk: List[Dict],
                     retry_on_transient: bool) -> Tuple[Optional[Dict[str, Tuple[str, str]]], str]:
    """청크(≤batch_size건) 1회 Gemma 호출 번역. (결과, 사유)를 반환한다.

    사유를 함께 돌려주는 이유: 호출부의 '개별 번역 폴백'은 배치 JSON이 깨졌을 때만
    의미가 있다. 429/503처럼 API 자체가 실패한 청크를 개별로 재시도하면 같은 오류를
    6배로 늘려 한도만 더 태운다(429가 429를 부르는 증폭). 사유가 있어야 구분된다.

    사유: "ok"(성공) · "parse"(응답 형식 파손 → 개별 폴백 가치 있음) ·
          "api"(호출 실패 → 개별 폴백 무의미) · "skip"(일일 한도 소진)
    응답 JSON에서 누락된 항목은 영문 폴백으로 채워 성공 시 반환값은 청크 전체를 커버한다."""
    # 입력 500자·출력 2줄 요약으로 제한 — 배치당 생성 토큰을 줄여 호출당 소요를 절반 이하로
    # (관측: 출력이 크면 배치당 ~60초 → 40청크에 40분, 실행 타임아웃의 주범이었음)
    numbered = "\n".join(
        f"{n}. Title: {it['title']} / Desc: {(it['description'] or '')[:500]}"
        for n, it in enumerate(chunk, 1)
    )
    prompt = f"""You are a translator that outputs ONLY valid JSON. No markdown, no code fences, no commentary.
For EACH numbered CVE below, translate its Title into Korean and summarize its Description into Korean (each max 2 short lines).
Keep technical terms in English or Korean transliteration (e.g., "버퍼 오버플로우", "SQL 인젝션") — do NOT translate them literally.
Output EXACTLY one JSON array with {len(chunk)} objects in the same order, and nothing else:
[{{"n":1,"title_ko":"...","desc_ko":"..."}}{',...' if len(chunk) > 1 else ''}]

CVEs:
{numbered}"""
    max_attempts = 3 if retry_on_transient else 1
    for attempt in range(1, max_attempts + 1):
        try:
            if not rate_limit_manager.check_and_wait("gemini"):
                return None, "skip"
            response = gemini_client.models.generate_content(
                model=config.MODEL_PHASE_0,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=3072,  # 6건 × 제목+2줄 요약 — 잘림 방지(JSON 완결)
                    temperature=0.3,
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )]
                )
            )
            tokens = 0
            usage = getattr(response, "usage_metadata", None)
            if usage is not None:
                tokens = getattr(usage, "total_token_count", 0) or 0
            rate_limit_manager.record_call("gemini", tokens_used=tokens)

            text = (response.text or "").strip()
            text = re.sub(r"```(?:json)?\s*\n?", "", text).strip()
            try:
                arr = json.loads(text)
            except json.JSONDecodeError:
                m = re.search(r'\[[\s\S]*\]', text)
                if not m:
                    logger.warning(f"일괄 번역 파싱 실패 (JSON 배열 없음, 시도 {attempt})")
                    return None, "parse"
                arr = json.loads(m.group())

            if not isinstance(arr, list):
                return None, "parse"
            by_n = {int(o.get('n', 0)): o for o in arr if isinstance(o, dict)}
            out: Dict[str, Tuple[str, str]] = {}
            for n, it in enumerate(chunk, 1):
                o = by_n.get(n, {})
                title_ko = (o.get('title_ko') or '').strip() or it['title']
                desc_ko = (o.get('desc_ko') or '').strip() or (it['description'] or '')[:200]
                out[it['id']] = (title_ko, desc_ko)
            return out, "ok"

        except json.JSONDecodeError as e:
            # 폴백 정규식으로 뽑은 조각도 JSON이 아니었다 = 응답 형식 문제
            logger.warning(f"일괄 번역 파싱 실패: {e}")
            return None, "parse"
        except Exception as e:
            msg = str(e)
            kind = _gemini_error_kind(msg)
            if kind == "rpd":
                rate_limit_manager.mark_rpd_exhausted("gemini")
                logger.warning("일괄 번역 일일 한도(RPD) 소진 — 이후 번역은 영문 폴백")
                return None, "skip"
            if kind in ("rate", "transient") and attempt < max_attempts:
                wait = _gemini_backoff(kind, attempt, msg)
                logger.warning(f"일괄 번역 {kind} 오류({attempt}/{max_attempts}): {e} → {wait:.0f}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"일괄 번역 청크 실패({kind}): {e}")
            return None, kind
    return None, "api"

# ==============================================================================
# [3] GitHub Issue 생성/업데이트
# ==============================================================================

# CVE → 패키지·수정버전 사전 (주간 워크플로가 만들어 Pages에 배포하는 파일).
# 리포트에 "어디까지 올리면 되는지"를 싣기 위한 것 — 공개 정적 파일이라 DB 호출 0.
_PKG_INDEX: Optional[Dict] = None


def _package_index() -> Dict:
    """CVE→패키지 사전을 1회 읽어 캐시. 못 구하면 빈 dict(기능만 조용히 생략).

    배포본을 먼저 본다. 데이터 파일을 더는 커밋하지 않으므로 체크아웃에는 없거나
    옛날 것이다. 로컬 실행처럼 배포본을 못 받는 경우를 위해 파일 경로도 남긴다."""
    global _PKG_INDEX
    if _PKG_INDEX is not None:
        return _PKG_INDEX

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        url = f"https://{owner.lower()}.github.io/{name}/data/cve-packages.json"
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "argus-report"})
            with urllib.request.urlopen(req, timeout=180) as r:
                _PKG_INDEX = (json.loads(r.read().decode("utf-8")) or {}).get("packages") or {}
            logger.info(f"패키지 사전 로드(배포본): {len(_PKG_INDEX):,}건")
            return _PKG_INDEX
        except Exception as e:
            logger.warning(f"패키지 사전 배포본 로드 실패({e}) → 체크아웃 사본 확인")

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "docs", "data", "cve-packages.json")
    try:
        with open(path, encoding="utf-8") as f:
            _PKG_INDEX = (json.load(f) or {}).get("packages") or {}
        logger.info(f"패키지 사전 로드(파일): {len(_PKG_INDEX):,}건")
    except (OSError, ValueError):
        _PKG_INDEX = {}
    return _PKG_INDEX


def _fixed_version_lines(cve_id: str) -> str:
    """OSV가 알려주는 수정 버전. 체크리스트의 '패치 적용'에 목표가 없으면 무용지물이라
    리포트에 함께 싣는다. 사전에 없으면 빈 문자열 → 블록 자체가 생략된다."""
    pkgs = _package_index().get(cve_id) or {}
    lines = []
    for pkg, eco_map in sorted(pkgs.items()):
        for eco, fixes in sorted((eco_map or {}).items()):
            good = [f for f in (fixes or []) if f]
            if good:
                lines.append(f"| `{pkg}` | {eco} | **{', '.join(good)}** |")
    if not lines:
        return ""
    return ("\n## 📦 패치 버전 (OSV)\n"
            "| 패키지 | 배포판·생태계 | 이 버전 이상으로 |\n| :--- | :--- | :--- |\n"
            + "\n".join(lines[:12])
            + "\n\n<sub>출처: [OSV.dev](https://osv.dev) (CC-BY 4.0) — 설치된 배포판·릴리스에 "
              "맞는 행을 보세요. 실제 적용 전 벤더 권고를 확인하시기 바랍니다.</sub>\n")


def _rule_license_note(rule_info: Dict) -> str:
    """공식 룰 재게시 시 출처·author·라이선스 고지 보존 (불변 원칙 8-①)"""
    lic = rule_info.get('license')
    if not lic:
        return ""
    return f"\n> **License:** {lic} — 원 룰의 출처·author·라이선스 고지를 보존합니다.\n"

def _priority_banner(cve_data: Dict) -> str:
    """실제 악용 신호 조합으로 대응 우선순위를 산출 (AI 호출 없이 기존 필드만 사용).

    이슈를 여는 즉시 '오늘 패치 vs 이번 주'를 판단하게 해준다. 판정 축은 _risk_tier와
    동일한 신호(KEV/무기화/PoC·EPSS/CVSS)를 쓰되, 실무 대응 시급성 기준으로 더 세분한다."""
    if cve_data.get('is_kev'):
        level, why = "🔴 즉시 대응", "CISA KEV 등재 — 실제 악용 확인됨"
    elif cve_data.get('ssvc_exploitation') == 'active' or cve_data.get('has_metasploit_module'):
        level, why = "🔴 긴급", "무기화·악용 진행형 신호 존재 (SSVC active / Metasploit)"
    elif (cve_data.get('has_public_exploit') or cve_data.get('has_poc')
          or cve_data.get('epss', 0.0) >= 0.1):
        level, why = "🟠 높음", "공개 익스플로잇·PoC 또는 EPSS 급증 — 악용 가능성 상승"
    elif cve_data.get('cvss', 0.0) >= 9.0:
        level, why = "🟠 높음", "CVSS Critical (악용 신호는 아직 미확인)"
    else:
        level, why = "🟡 주의", "고위험 점수, 실제 악용 신호는 미확인"
    return f"> **⚡ 대응 우선순위: {level}** — {why}"

def _epss_caption(cve_data: Dict) -> str:
    """EPSS 숫자에 의미를 붙인다 — 신규 CVE는 낮은 게 정상이라 오해 방지 (FIRST.org 출처)."""
    epss = cve_data.get('epss', 0.0) or 0.0
    surge = " · **⚠️ 급증**" if epss >= 0.1 else ""
    return f"<sub>EPSS {epss*100:.2f}% — 향후 30일 내 실제 악용 시도 확률 (출처: FIRST.org){surge}</sub>"

def _issue_labels(cve_data: Dict) -> List[str]:
    """이슈 트리아지용 동적 라벨 — 심각도 + 실제 악용 신호.
    이슈가 다수 쌓여도 `label:kev`·`label:severity:critical` 등으로 필터 가능.
    (GitHub는 이슈 생성 시 없는 라벨을 자동 생성하므로 사전 등록 불필요.)"""
    score = cve_data.get('cvss', 0.0) or 0.0
    labels = ["security", "cve"]
    labels.append("severity:critical" if score >= 9.0
                  else "severity:high" if score >= 7.0 else "severity:medium")
    if cve_data.get('is_kev'):
        labels.append("kev")
    if cve_data.get('has_metasploit_module') or cve_data.get('ssvc_exploitation') == 'active':
        labels.append("exploited")
    if cve_data.get('has_public_exploit') or cve_data.get('has_poc'):
        labels.append("poc")
    return labels

def create_github_issue(cve_data: Dict, reason: str) -> Tuple[Optional[str], Optional[Dict]]:
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    
    if not repo:
        logger.warning("GITHUB_REPOSITORY 미설정, Issue 생성 건너뜀")
        return None, None
    
    try:
        # Step 1: AI 심층 분석 (핵심 산출물 — 근본원인·공격 시나리오·MITRE·벡터)
        logger.info(f"AI 분석 시작: {cve_data['id']}")
        analyzer = Analyzer()
        analysis = analyzer.analyze_cve(cve_data)

        # Step 2: 공개 탐지 룰 검색만 (AI 룰 생성 없음 — 공개 룰 있을 때만 채움)
        rule_manager = RuleManager()
        rules = rule_manager.search_public_only(cve_data['id'])

        # Step 3: 공식 룰 존재 여부 확인
        has_official = any([
            rules.get('sigma') and rules['sigma'].get('verified'),
            any(r.get('verified') for r in rules.get('network', [])),  # network는 리스트!
            rules.get('yara') and rules['yara'].get('verified')
        ])
        
        # Step 4: 마크다운 리포트 구성
        body = _build_issue_body(cve_data, reason, analysis, rules)
        
        # Step 5: GitHub API 호출
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}",
            "body": body,
            "labels": _issue_labels(cve_data)
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        
        issue_url = response.json().get("html_url")
        logger.info(f"GitHub Issue 생성 성공: {issue_url}")
        
        return issue_url, {"has_official": has_official, "rules": rules}
        
    except Exception as e:
        logger.error(f"GitHub Issue 생성 실패: {e}")
        return None, None

def _build_issue_body(cve_data: Dict, reason: str, analysis: Dict, rules: Dict) -> str:
    # CVSS 배지 색상
    score = cve_data['cvss']
    if score >= 9.0: color = "FF0000"
    elif score >= 7.0: color = "FD7E14"
    elif score >= 4.0: color = "FFC107"
    elif score > 0: color = "28A745"
    else: color = "CCCCCC"
    
    kev_color = "FF0000" if cve_data['is_kev'] else "CCCCCC"

    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{cve_data['epss']*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data['is_kev'] else 'No'}-{kev_color})"

    # P5 위협 신호 배지
    if cve_data.get('ssvc_exploitation') == 'active':
        badges += " ![SSVC](https://img.shields.io/badge/SSVC-Active-red)"
    if cve_data.get('has_metasploit_module'):
        badges += " ![Metasploit](https://img.shields.io/badge/Metasploit-Weaponized-8B0000)"
    if cve_data.get('has_public_exploit'):
        badges += " ![ExploitDB](https://img.shields.io/badge/ExploitDB-Public-orange)"

    # 위협 신호 상세 (출처 표기 — Metasploit metadata는 BSD-3-Clause)
    signal_lines = []
    ssvc = cve_data.get('ssvc') or {}
    if ssvc:
        parts = [f"{k}={v}" for k, v in ssvc.items()]
        signal_lines.append(f"- **CISA SSVC** (vulnrichment, CC0): {', '.join(parts)}")
    if cve_data.get('has_metasploit_module'):
        mods = cve_data.get('metasploit_modules', [])
        mod_str = ", ".join(f"`{m}`" for m in mods) if mods else "존재"
        signal_lines.append(f"- **Metasploit 모듈** (Metasploit Framework, Rapid7, BSD-3-Clause): {mod_str}")
    if cve_data.get('has_public_exploit'):
        edb_url = cve_data.get('_exploit_db_url')
        link = f" — [Exploit-DB]({edb_url})" if edb_url else ""
        signal_lines.append(f"- **공개 익스플로잇**: ExploitDB 등재{link}")
    if cve_data.get('has_poc'):
        # PoC 원문은 재게시하지 않고 출처 링크만 표기 (불변 원칙 8-②)
        poc_urls = cve_data.get('poc_urls', [])
        poc_link = f" — [PoC 링크]({poc_urls[0]})" if poc_urls else ""
        signal_lines.append(
            f"- **PoC 공개** (출처: nomi-sec/trickest, 원문 미게시·링크만): "
            f"{cve_data.get('poc_count', len(poc_urls))}건{poc_link}")
    threat_signals = ("## 🧨 위협 신호\n" + "\n".join(signal_lines) + "\n") if signal_lines else ""

    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    
    # 영향받는 자산 테이블
    affected_rows = ""
    for item in cve_data.get('affected', []):
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} |\n"
    if not affected_rows:
        affected_rows = "| - | - | - |"

    # OSV 수정 버전 — 없으면 빈 문자열이라 블록이 통째로 빠진다
    fixed_block = _fixed_version_lines(cve_data['id'])
    patch_hint = ""
    if fixed_block:
        patch_hint = " *(목표 버전은 아래 '패치 버전' 표 참조)*"

    # 대응 방안
    mitigation_list = "\n".join([f"- {m}" for m in analysis.get('mitigation', [])])
    
    # 참고 자료 (PoC·Exploit-DB는 원문 대신 링크만 게시 — 불변 원칙 8-②)
    # URL 기준 dedup: PoC/EDB URL이 references에 이미 있으면 그 자리에 주석만 병기(중복 행 방지),
    # references에 없으면 새 행으로 추가. → 링크는 1회만, 출처 주석은 유실 없이 보존.
    notes = {}
    if cve_data.get('_exploit_db_url'):
        notes[cve_data['_exploit_db_url']] = " (Exploit-DB PoC)"
    for u in cve_data.get('poc_urls', [])[:3]:
        notes.setdefault(u, " (PoC, nomi-sec/trickest)")
    ref_items = []
    seen = set()
    for r in cve_data['references']:
        if r and r not in seen:
            ref_items.append(f"{r}{notes.get(r, '')}")
            seen.add(r)
    for u, note in notes.items():          # references에 없던 PoC/EDB 링크만 추가
        if u not in seen:
            ref_items.append(f"{u}{note}")
            seen.add(u)
    ref_list = "\n".join([f"- {r}" for r in ref_items]) if ref_items else "- 등록된 참고 링크 없음"

    # CVSS 벡터 해석
    vector_details = parse_cvss_vector(cve_data.get('cvss_vector', 'N/A'))
    
    # 공개 탐지 룰 섹션 — 공개 룰(SigmaHQ/ET Open/Yara-Rules)이 있을 때만 표시.
    # AI 룰 생성은 제거됨 → 공개 룰이 없으면 없음을 안내(불필요한 '미생성' 나열 제거).
    has_any_rules = rules.get('sigma') or rules.get('network') or rules.get('yara')
    if has_any_rules:
        rules_section = ("## 🔎 공개 탐지 룰\n\n"
                         "> 공개 룰셋(SigmaHQ / ET Open / Yara-Rules)에서 확인된 **공식 검증 룰**입니다. "
                         "보안 장비 적용 전 자사 환경에 맞게 검토하세요.\n\n")
        if rules.get('sigma'):
            info = rules['sigma']
            rules_section += f"### Sigma Rule ({info['source']}) 🟢 공식 검증\n{_rule_license_note(info)}```yaml\n{info['code']}\n```\n\n"
        if rules.get('network'):
            for idx, net_rule in enumerate(rules['network'], 1):
                engine_name = net_rule.get('engine', 'unknown').upper()
                rules_section += f"### Network Rule #{idx} ({net_rule['source']} - {engine_name}) 🟢 공식 검증\n{_rule_license_note(net_rule)}```bash\n{net_rule['code']}\n```\n\n"
        if rules.get('yara'):
            info = rules['yara']
            rules_section += f"### Yara Rule ({info['source']}) 🟢 공식 검증\n{_rule_license_note(info)}```yara\n{info['code']}\n```\n\n"
    else:
        rules_section = ("## 🔎 공개 탐지 룰\n\n"
                         "> 현재 공개 룰셋(SigmaHQ / ET Open / Yara-Rules)에서 이 CVE에 대한 탐지 룰은 확인되지 않았습니다. "
                         "공개 룰이 등록되면 정기 재확인 시 자동 반영됩니다. 그 전에는 위의 분석·공격 시나리오·대응 방안을 참고하세요.\n")

    now_kst = datetime.datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S (KST)')

    # 대응 우선순위 배너 + EPSS 의미 캡션
    priority = _priority_banner(cve_data)
    epss_caption = _epss_caption(cve_data)

    # 취약점 개요 — AI 해석(근본원인)의 대조 기준이 되는 원문. desc_ko(한글) 우선,
    # 영문 원문은 <details>로 접어 제공(한글 폴백으로 둘이 같으면 영문 블록 생략).
    desc_ko = (cve_data.get('desc_ko') or '').strip()
    desc_en = (cve_data.get('description') or '').strip()
    overview_section = ""
    if desc_ko and desc_ko != 'N/A':
        overview_section = f"## 📄 취약점 개요\n{desc_ko}\n"
        if desc_en and desc_en != 'N/A' and desc_en != desc_ko:
            overview_section += f"\n<details><summary>원문 (English)</summary>\n\n> {desc_en}\n\n</details>\n"
        overview_section += "\n"
    elif desc_en and desc_en != 'N/A':
        overview_section = f"## 📄 취약점 개요\n{desc_en}\n\n"

    body = f"""# 🛡️ {cve_data['title_ko']}

> **탐지 일시:** {now_kst}
> **탐지 사유:** {reason}

{priority}

{badges}
{epss_caption}

**취약점 유형 (CWE):** {cwe_str}

{threat_signals}
{overview_section}## 📦 영향 받는 자산 (벤더 / 제품 / 버전)
| 벤더 | 제품 | 버전 |
| :--- | :--- | :--- |
{affected_rows}
{fixed_block}
## 🔍 AI 심층 분석
### 기술적 근본 원인
{analysis.get('root_cause', '-')}

### 🎯 공격 벡터 상세
| 항목 | 내용 |
| :--- | :--- |
| **공식 벡터** | `{cve_data.get('cvss_vector', 'N/A')}` |
| **상세 해석** | {vector_details} |

### 🏹 공격 시나리오 (MITRE ATT&CK)
{analysis.get('scenario', '정보 없음')}

### 💥 비즈니스 영향
{analysis.get('impact', '-')}

## 🛡️ 권고 대응 방안
{mitigation_list}

## ✅ 조치 체크리스트
<!-- 이 이슈를 그대로 작업 티켓으로 사용하세요. -->
- [ ] 영향 자산 식별 (위 '영향 받는 자산'과 사내 인벤토리 대조)
- [ ] 노출 여부 확인 (해당 서비스가 외부에 열려 있는지)
- [ ] 패치·완화 조치 적용 (위 권고 대응 방안 참조){patch_hint}
- [ ] 탐지 룰 배포 (아래 공개 탐지 룰이 있는 경우)
- [ ] 조치 결과 기록 후 이슈 종료

{rules_section}

## 🔗 참고 자료
{ref_list}

---
<sub>📊 **데이터 출처**: CVE(cvelistV5, CC0) · NVD(NIST, 공공) · CISA KEV·SSVC/vulnrichment(공공/CC0) ·
EPSS([FIRST.org](https://www.first.org/epss/)) · [OSV.dev](https://osv.dev)(CC-BY 4.0) ·
GitHub Advisory · Metasploit(Rapid7, BSD-3) ·
PoC/ExploitDB(원문 미게시·링크만). 공개 탐지 룰은 각 출처·라이선스 고지를 보존합니다.
AI 분석·위험도 분류는 **참고용**이며 정확성을 보증하지 않습니다.</sub>
"""
    return body.strip()

def update_github_issue_with_official_rules(issue_url: str, cve_id: str, rules: Dict) -> bool:
    comment = f"""## ✅ 공식 탐지 룰 발견

{cve_id}에 대한 **공식 검증된 탐지 룰**이 새로 발견되었습니다. 아래 룰을 보안 장비에 참고 적용하세요.

"""
    
    # Sigma
    if rules.get('sigma') and rules['sigma'].get('verified'):
        comment += f"### Sigma Rule ({rules['sigma']['source']})\n{_rule_license_note(rules['sigma'])}```yaml\n{rules['sigma']['code']}\n```\n\n"

    # Network (여러 개 가능)
    if rules.get('network'):
        for idx, net_rule in enumerate(rules['network'], 1):
            if net_rule.get('verified'):
                engine = net_rule.get('engine', 'unknown').upper()
                comment += f"### Network Rule #{idx} ({net_rule['source']} - {engine})\n{_rule_license_note(net_rule)}```bash\n{net_rule['code']}\n```\n\n"

    # Yara
    if rules.get('yara') and rules['yara'].get('verified'):
        comment += f"### Yara Rule ({rules['yara']['source']})\n{_rule_license_note(rules['yara'])}```yara\n{rules['yara']['code']}\n```\n\n"
    
    notifier = SlackNotifier()
    return notifier.update_github_issue(issue_url, comment)

# ==============================================================================
# [4] CVE 처리 (단일)
# ==============================================================================

# last_alert_state(JSONB)에 저장할 필드 화이트리스트 — DB 용량 최소화.
# 대시보드 표시용(export_dashboard_data) + 다음 실행 에스컬레이션 비교용(_should_send_alert)만 포함.
# 제외: id(중복)·cvss_vector·references·poc_count·is_vulncheck_kev·github_advisory·nvd_cpe (미표시/미비교).
_DASHBOARD_STATE_FIELDS = frozenset({
    # 대시보드 표시
    "title", "title_ko", "description", "desc_ko", "cwe", "affected",
    "has_poc", "poc_urls", "ssvc", "ssvc_exploitation",
    "has_public_exploit", "has_metasploit_module", "metasploit_modules",
    # 자동화 악용 축 — 위험도 판정(_risk_tier)과 대시보드 딱지에 사용
    "ssvc_automatable", "ssvc_technical_impact", "is_kev_ransomware",
    # CVE 공개일 — 추이 차트 전용 (표/필터의 '확인일'과 별개)
    "published",
    # 공격 벡터 시각화용 (모달 칩). 문자열 1개(~60B)라 용량 영향 미미
    "cvss_vector",
    # 자산 매칭 종류("asset"/"wildcard") — 대시보드 '내 자산' 패널용.
    # is_target_asset의 판정을 그대로 싣는다(프론트에서 매칭을 재구현하면 기준이 갈라짐).
    "match_type",
    # 에스컬레이션 비교용 (다음 실행에서 last_state로 참조)
    "cvss", "epss", "is_kev",
})

def prepare_single_cve(cve_id: str, collector: Collector, db: ArgusDB) -> Dict:
    """Phase A — 수집·분류·(알림 대상만) 위협인텔까지. 번역/완성은 별도 단계.

    반환 stage:
      "done"  → 여기서 처리 종료(비발행/비대상/T3 최소갱신/보류). status 포함.
      "ready" → 번역(Phase B)·완성(Phase C) 대기. current_state 등 컨텍스트 포함.
    번역을 배치(Phase B)로 묶기 위한 분리다 — 개별 번역은 Gemma RPM 15에 묶여
    실행당 8분+를 소모하고 RPD 1,500도 초과해 처리 상한을 올릴 수 없었다."""
    try:
        # Step 1: CVE 상세 정보 수집
        raw_data = collector.enrich_cve(cve_id)

        # 수집 실패(네트워크 등) → failed로 워터마크가 붙잡아 다음 실행 재수집 (누락 0).
        # 404/비발행 등 정상적으로 처리할 게 없는 상태는 handled로 통과(워터마크 전진).
        if raw_data.get('state') == 'ERROR':
            logger.warning(f"{cve_id}: 수집 실패 → failed (다음 실행 재수집)")
            return {"cve_id": cve_id, "status": "failed", "stage": "done"}
        if raw_data.get('state') != 'PUBLISHED':
            logger.debug(f"{cve_id}: PUBLISHED 상태 아님, 건너뜀")
            return {"cve_id": cve_id, "status": "handled", "stage": "done"}

        # Step 2: 자산 필터링 (affected vendor/product 우선, NVD CPE 보조, description 보조)
        # 유효 벤더가 없으면 NVD CPE를 조회해 affected를 채운다 — 매칭 소스 확보이자
        # 대시보드 벤더 필터·리포트 표시를 위한 것이다(_needs_cpe_lookup 주석 참조).
        if _needs_cpe_lookup(raw_data):
            collector.fill_affected_from_nvd(raw_data)
        is_target, match_info, match_type = is_target_asset(raw_data)
        if not is_target:
            logger.debug(f"{cve_id}: 감시 대상 아님, 건너뜀")
            return {"cve_id": cve_id, "status": "handled", "stage": "done"}

        # Step 2.5: 값싼 위험 신호만 먼저 (메모리/캐시, 네트워크 0) — 고위험 판별용.
        # 값비싼 위협인텔(NVD/PoC/Advisory)은 고위험으로 판정된 CVE에만 이후 수집 → 처리량 확보.
        collector.enrich_cheap_signals(raw_data)

        # Step 3: 현재 상태 구성 (값싼 신호까지; PoC/Advisory/NVD-CPE는 고위험만 이후 보강)
        current_state = {
            "id": cve_id,
            "title": raw_data['title'],
            "cvss": raw_data['cvss'],
            "cvss_vector": raw_data['cvss_vector'],
            "is_kev": cve_id in collector.kev_set,
            "epss": collector.epss_cache.get(cve_id, 0.0),
            "description": raw_data['description'],
            "cwe": raw_data['cwe'],
            "references": raw_data['references'],
            "affected": raw_data['affected'],
            "has_poc": raw_data.get('has_poc', False),
            "poc_count": raw_data.get('poc_count', 0),
            "poc_urls": raw_data.get('poc_urls', []),
            "is_vulncheck_kev": raw_data.get('is_vulncheck_kev', False),
            "github_advisory": raw_data.get('github_advisory', {}),
            "nvd_cpe": raw_data.get('nvd_cpe', []),
            # 공개일 — 추이 차트 전용 (표/필터는 확인일 기준 유지)
            "published": raw_data.get('published', ''),
            # P5 데이터 소스 확대 신호
            "ssvc": raw_data.get('ssvc', {}),
            "ssvc_exploitation": (raw_data.get('ssvc') or {}).get('exploitation'),
            # SSVC의 나머지 두 축 — CISA가 CVE마다 판정해 붙여주는데 그동안 리포트에
            # 글자로만 찍히고 판정에는 쓰이지 않았다. automatable은 "정찰~익스플로잇을
            # 신뢰성 있게 자동화할 수 있는가"라, CVSS가 낮아도 대량 공격 대상이 된다.
            "ssvc_automatable": (raw_data.get('ssvc') or {}).get('automatable'),
            "ssvc_technical_impact": (raw_data.get('ssvc') or {}).get('technical_impact'),
            "is_kev_ransomware": raw_data.get('is_kev_ransomware', False),
            "has_public_exploit": raw_data.get('has_public_exploit', False),
            "has_metasploit_module": raw_data.get('has_metasploit_module', False),
            "metasploit_modules": raw_data.get('metasploit_modules', []),
            # 자산 매칭 판정 — 대시보드 '내 자산' 패널이 이 값을 그대로 쓴다
            "match_type": match_type,
            # ExploitDB 링크(원문 미게시, 링크만 — 8-②). '_' 접두라 DB 저장에서 자동 제외.
            "_exploit_db_url": raw_data.get('_exploit_db_url'),
        }
        
        # Step 4: 티어 분류 + 알림 필요성 판단
        last_record = db.get_cve(cve_id)
        last_state = last_record.get('last_alert_state') if last_record else None

        tier = _risk_tier(current_state)
        should_alert, alert_reason, full_report = _should_send_alert(
            current_state, last_state, match_type, tier
        )

        # 알림 트리거 없음 → 자산 기준 티어링:
        #   - 추적 중(last_state 보유 = 추적 or 과거 알림): 최소 갱신(T3).
        #   - 비자산(wildcard) 미추적 + low: 마커만 저장 — 번역/위협인텔/대시보드 없음.
        #     마커(상태 없는 행)는 재커밋 dedup용이며, 레코드가 바뀌면 '신규'로 재분류된다.
        #   - 그 외(high 티어 전체, 자산 low, 과거 마커의 자산 승격): 아래로 진행해
        #     추적 시작(번역+대시보드; high는 Slack 배치 요약에 건수 집계).
        # T3와 마커의 저장 payload는 동일(스칼라+해시) — last_alert_state 부재가 마커의 정의.
        if not should_alert:
            is_tracked = last_state is not None
            if is_tracked or (match_type == "wildcard" and tier == "low"):
                saved = db.upsert_cve({
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "updated_at": datetime.datetime.now(KST).isoformat(),
                    "content_hash": raw_data.get('content_hash')
                })
                # 저장 실패 = 미처리 → 워터마크가 붙잡아 다음 실행에서 재시도 (누락 방지)
                return {"cve_id": cve_id, "status": "handled" if saved else "failed",
                        "stage": "done", "skipped_low_wildcard": not is_tracked}

        # 고위험/에스컬레이션(should_alert)만 값비싼 위협인텔(NVD/PoC/Advisory) 풀 수집 → 상태 보강.
        # 저위험(T2)은 생략해 처리량 확보(번역은 유지). NVD가 CVSS를 보정할 수 있으나 고위험만 필요.
        if should_alert:
            raw_data = collector.enrich_threat_intel(raw_data)
            current_state.update({
                "cvss": raw_data['cvss'],            # NVD 보정 반영
                "cvss_vector": raw_data['cvss_vector'],
                "cwe": raw_data['cwe'],
                "affected": raw_data['affected'],    # CPE 벤더 보강 반영
                "has_poc": raw_data.get('has_poc', False),
                "poc_count": raw_data.get('poc_count', 0),
                "poc_urls": raw_data.get('poc_urls', []),
                "github_advisory": raw_data.get('github_advisory', {}),
                "nvd_cpe": raw_data.get('nvd_cpe', []),
            })

        # 여기 도달 = (1) 알림 대상(critical/자산high/에스컬레이션), 또는 (2) 추적 대상
        # (high 단독·자산 low). → 번역(Phase B, 배치)과 완성(Phase C)으로 넘긴다.
        if should_alert:
            logger.info(f"알림 발송 준비: {cve_id} ({alert_reason}, Report: {full_report})")
        return {
            "cve_id": cve_id, "stage": "ready",
            "current_state": current_state, "raw_data": raw_data,
            "should_alert": should_alert, "alert_reason": alert_reason,
            "full_report": full_report, "tier": tier,
        }

    except Exception as e:
        logger.error(f"{cve_id} 준비 실패: {e}", exc_info=True)
        # 실패 = 미처리 → 워터마크가 이 CVE를 건너뛰지 않아야 다음 실행에서 재시도됨
        return {"cve_id": cve_id, "status": "failed", "stage": "done"}


def finalize_single_cve(prep: Dict, translation: Optional[Tuple[str, str]],
                        db: ArgusDB, notifier: SlackNotifier) -> Dict:
    """Phase C — 번역 결과 반영 후 Issue/Slack/DB 저장. prep은 prepare_single_cve의 ready 반환값.

    translation이 None이면(배치 번역 실패 등) 영문 폴백 — 기존 단건 번역 실패 폴백과 동일 정책."""
    cve_id = prep["cve_id"]
    try:
        current_state = prep["current_state"]
        raw_data = prep["raw_data"]
        should_alert = prep["should_alert"]
        alert_reason = prep["alert_reason"]
        full_report = prep["full_report"]

        # Step 5b: 번역 반영 (배치 결과 또는 영문 폴백)
        if translation is None:
            translation = (current_state['title'], (current_state.get('description') or '')[:200])
        current_state['title_ko'], current_state['desc_ko'] = translation

        # Step 6: 풀 리포트 대상(critical/자산high)만 GitHub Issue (AI 심층 분석 + 공개 룰) 생성
        report_url = None
        rules_info = None
        if should_alert and full_report:
            # 분석 티어(Gemini 주력 + Groq 비상)가 전부 소진됐을 때만 Issue 보류.
            # 한쪽만 소진이면 다른 쪽이 분석하므로 알림이 지연되지 않는다 — 그래서 조건이
            # AND다(어느 쪽이 주력인지와 무관하게 '둘 다 불가'만 잡는다).
            # 보류 시 Slack/DB저장 없이 failed로 반환해 워터마크가 붙잡고 다음 실행에서 완전 재처리
            # (Slack 미발송 → 중복알림 없음, content_hash 미저장 → 재수집됨 → 누락 없음).
            if (rate_limit_manager.active_groq_model(config.GROQ_MODELS) is None
                    and rate_limit_manager.is_rpd_exhausted("gemini_analysis")):
                logger.warning(f"⚠️ {cve_id}: 분석 티어 전부 소진 → Issue 보류(다음 실행 재처리)")
                return {"cve_id": cve_id, "status": "failed"}
            report_url, rules_info = create_github_issue(current_state, alert_reason)

        # Step 7: Slack 알림 (알림 대상만 — 저위험 신규는 발송 안 함).
        # 긴급 여부는 파이프라인이 이미 판정한 티어를 그대로 넘긴다 — 리포트의 '🔴 긴급'과
        # Slack 즉시 알림이 서로 다른 기준으로 갈라지지 않게.
        if should_alert:
            notifier.send_alert(current_state, alert_reason, report_url,
                                urgent=(prep.get("tier") == "critical"))

        # Step 8: DB 저장 (content_hash 포함)
        # last_alert_state(JSONB)에는 대시보드 표시 + 다음 실행 에스컬레이션 비교에 필요한 필드만
        # 저장한다 — DB 용량 최소화(불변 원칙 2). github_advisory/references/nvd_cpe/cvss_vector 등
        # 대시보드·비교에 안 쓰는 큰 필드와 임시 컨텍스트(_로 시작)는 제외. PoC 원문 미저장(8-②).
        clean_state = {k: current_state[k] for k in _DASHBOARD_STATE_FIELDS if k in current_state}

        db_data = {
            "id": cve_id,
            "cvss_score": current_state['cvss'],
            "epss_score": current_state['epss'],
            "is_kev": current_state['is_kev'],
            "last_alert_state": clean_state,
            "updated_at": datetime.datetime.now(KST).isoformat(),
            "content_hash": raw_data.get('content_hash')
        }
        if should_alert:
            db_data["last_alert_at"] = datetime.datetime.now(KST).isoformat()
            db_data["report_url"] = report_url

        if rules_info:
            db_data["has_official_rules"] = rules_info.get('has_official', False)
            db_data["rules_snapshot"] = rules_info.get('rules')
            db_data["last_rule_check_at"] = datetime.datetime.now(KST).isoformat()

        saved = db.upsert_cve(db_data)
        if not saved:
            # 저장 실패 = DB/대시보드에 영구 미반영 위험 → failed로 워터마크가 붙잡아 재처리.
            # (T1은 알림이 이미 나갔으므로 재실행 시 content_hash 미저장 → 재처리되지만
            #  escalation 비교 기준(last_state)이 그대로라 중복 알림은 '신규' 케이스에 한정됨)
            return {"cve_id": cve_id, "status": "failed"}

        # 고위험 알림 = success, 저위험 추적 = handled (둘 다 워터마크 전진 대상)
        return {"cve_id": cve_id, "status": "success" if should_alert else "handled"}

    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        # 실패 = 미처리 → 워터마크가 이 CVE를 건너뛰지 않아야 다음 실행에서 재시도됨
        return {"cve_id": cve_id, "status": "failed"}


def process_single_cve(cve_id: str, collector: Collector, db: ArgusDB, notifier: SlackNotifier) -> Optional[Dict]:
    """단건 처리 경로 (에스컬레이션 스윕 등 소량 호출용) — prepare → 단건 번역 → finalize.
    메인 배치 경로(_main Phase A/B/C)와 동일한 로직을 단건으로 잇는 래퍼다."""
    prep = prepare_single_cve(cve_id, collector, db)
    if prep.get("stage") != "ready":
        return {"cve_id": cve_id, "status": prep.get("status", "failed")}
    translation = generate_korean_summary(prep["current_state"], retry_on_transient=prep["should_alert"])
    return finalize_single_cve(prep, translation, db, notifier)

def _risk_tier(current: Dict) -> str:
    """위험 3단 티어. 실무 유입에서 CVSS 7점대는 하루 수백 건(CISA ADP가 무점수 CVE에
    7.x를 일괄 부여)이라, '진짜 긴급'과 'CVSS만 높음'을 분리해야 알림이 의미를 가진다.

    critical — 실제 악용/무기화 신호 또는 최상위 심각도. 풀 알림(Issue+AI분석+Slack).
    high     — CVSS 7~8.9 단독, 또는 자동화 악용 신호. 번역+대시보드 추적 + Slack 요약 건수만.
               (자산 등록 CVE는 high도 풀 알림 — 실제 대응 대상이므로.)
    low      — 그 외. 자산이면 추적, 비자산이면 마커.

    KEV 등재분의 약 11%가 CVSS 7 미만이라 점수만으로는 실제 악용을 놓친다. 그 중 악용
    신호가 붙은 것은 위 critical 조건이 이미 잡고, 여기서는 '아직 신호는 없지만 대량
    자동화가 가능한' 저위험을 high로 끌어올려 대시보드에 보이게 한다. 알림은 늘지 않는다.
    """
    if (current['is_kev']
            or current.get('has_metasploit_module')
            or current.get('ssvc_exploitation') == 'active'
            or current.get('epss', 0.0) >= 0.1
            or current['cvss'] >= 9.0):
        return "critical"
    # CISA SSVC Automatable=yes → 정찰~익스플로잇 자동화 가능. CVSS와 무관하게 추적한다.
    # (critical로 올리지 않는 이유: 아직 악용이 관측된 게 아니라 '가능하다'는 판정이라,
    #  알림 물량을 늘리기보다 화면에 세워두고 예측력을 관측한 뒤 정하는 편이 안전하다)
    if current['cvss'] >= 7.0 or current.get('ssvc_automatable') == 'yes':
        return "high"
    return "low"


def _should_send_alert(current: Dict, last: Optional[Dict],
                       match_type: Optional[str] = "wildcard",
                       tier: Optional[str] = None) -> Tuple[bool, str, bool]:
    """알림 판정. 반환: (알림 여부, 사유, full_report — Issue+AI분석 대상 여부).

    full_report = critical 티어 또는 자산 매칭 high. Slack-only 알림(예: 저위험의
    ExploitDB 등재 전환)은 알림은 가되 Issue는 만들지 않는다(기존 정책 유지)."""
    tier = tier or _risk_tier(current)
    full_report = tier == "critical" or (tier == "high" and match_type == "asset")

    # 신규 CVE: critical(또는 자산 high)만 알림. high 단독은 추적+요약, low는 추적/마커.
    if last is None:
        if tier == "critical":
            return True, "🆕 신규 Critical 취약점", True
        if tier == "high" and match_type == "asset":
            return True, "🆕 자산 High 취약점", True
        # 공개 익스플로잇이 이미 있는 채로 들어온 건. tier에는 반영하지 않는다 —
        # ExploitDB에는 오래된 PoC가 다수라 critical로 올리면 AI 분석 예산이 샌다.
        # 다만 '공격 코드가 이미 공개된 상태'를 조용히 넘기면 안 되므로 알림은 보낸다
        # (Issue 발행은 full_report 기준 — 전이 경로의 ExploitDB 정책과 동일).
        if current.get('has_public_exploit'):
            return True, "💥 신규 + ExploitDB 공개 익스플로잇", full_report
        return False, "", full_report

    # ── 에스컬레이션(전이) 트리거 — 실제 악용/무기화 신호는 항상 알림 ──
    # KEV 등재
    if current['is_kev'] and not last.get('is_kev'):
        return True, "🚨 KEV 등재", True

    # Metasploit 모듈 신규 등장 → 무기화됨
    if current.get('has_metasploit_module') and not last.get('has_metasploit_module'):
        return True, "🧨 Metasploit 모듈 공개 (무기화)", True

    # SSVC Exploitation active 전환 → 실제 악용 확인
    if current.get('ssvc_exploitation') == 'active' and last.get('ssvc_exploitation') != 'active':
        return True, "🎯 SSVC Exploitation=Active (실제 악용)", True

    # ExploitDB 공개 익스플로잇 신규 등장 (Slack 알림, Issue는 full_report일 때만)
    if current.get('has_public_exploit') and not last.get('has_public_exploit'):
        return True, "💥 ExploitDB 공개 익스플로잇", full_report

    # EPSS 임계 돌파 = critical 승격. 상승폭 조건만 두면 0.08 → 0.12처럼 완만하게
    # 넘어선 건이 빠진다(상승폭 0.04). 임계를 넘는 순간 자체를 트리거로 삼는다.
    if current['epss'] >= 0.1 and last.get('epss', 0) < 0.1:
        return True, "📈 EPSS 임계 돌파 (≥0.1)", True
    # 이미 임계 이상이던 건이 추가로 크게 오른 경우
    if current['epss'] >= 0.1 and (current['epss'] - last.get('epss', 0)) > 0.05:
        return True, "📈 EPSS 급증", True

    # CVSS 상향: Critical(≥9) 진입은 항상 알림, 7점대 진입은 자산 매칭만 알림
    # (비자산의 7점대 진입은 추적 승격으로 충분 — 하루 수백 건 노이즈 차단)
    if current['cvss'] >= 9.0 and last.get('cvss', 0) < 9.0:
        return True, "🔺 CVSS Critical 상향 (≥9)", True
    if match_type == "asset" and current['cvss'] >= 7.0 and last.get('cvss', 0) < 7.0:
        return True, "🔺 자산 CVSS 상향", True

    return False, "", full_report

# ==============================================================================
# [5] 공식 룰 재발견
# ==============================================================================

def check_for_official_rules() -> None:
    """
    공개(공식) 룰 재발견 체크.

    최초 리포트 시점에는 공개 룰셋(SigmaHQ/ET Open/Yara-Rules)에 룰이 없던 CVE도,
    시간이 지나면 룰이 등록되는 경우가 많다. 공개 룰 미확인 상태의 고위험 CVE를
    주기적으로 재검색해, 발견 시 기존 Issue에 댓글 + Slack 알림으로 반영한다.

    배치 제한: config 기반 (기본 10건)
    쿨다운: 성공 7일 / 실패 1일 (빠른 재시도)
    """
    try:
        logger.info("=== 공식 룰 재발견 체크 시작 ===")

        db = ArgusDB()
        notifier = SlackNotifier()
        rule_manager = RuleManager()

        # 배치 제한을 DB 조회로 밀어넣는다 — 후보 전량을 받아 파이썬에서 자르면
        # 고위험 수천 건 × 매시간 = Supabase egress 낭비 (불변 원칙 2)
        max_recheck = config.PERFORMANCE.get("max_rule_recheck", 10)
        candidates = db.get_rule_recheck_candidates(limit=max_recheck)

        if not candidates:
            logger.info("재확인 대상 없음")
            return
        logger.info(f"재확인 대상: {len(candidates)}건")

        found_count = 0

        for record in candidates:
            cve_id = record['id']

            try:
                # 공개 룰만 검색
                rules = rule_manager.search_public_only(cve_id)

                # 공식 룰 존재 확인
                has_official = any([
                    rules.get('sigma') and rules['sigma'].get('verified'),
                    any(r.get('verified') for r in rules.get('network', [])),
                    rules.get('yara') and rules['yara'].get('verified')
                ])

                now_iso = datetime.datetime.now(KST).isoformat()

                if has_official:
                    found_count += 1
                    logger.info(f"✅ {cve_id}: 공식 룰 발견!")

                    # 제목은 룰 발견 시에만 필요 → 후보 조회에서 제외하고 여기서 단건 조회.
                    # (보존정책으로 last_alert_state가 null일 수 있음 → cve_id 폴백)
                    full = db.get_cve(cve_id) or {}
                    title_ko = (full.get('last_alert_state') or {}).get('title_ko') or cve_id
                    notifier.send_official_rule_update(
                        cve_id=cve_id,
                        title=title_ko,
                        rules_info=rules,
                        original_report_url=record.get('report_url')
                    )

                    # GitHub Issue 업데이트
                    if record.get('report_url'):
                        update_github_issue_with_official_rules(
                            record['report_url'],
                            cve_id,
                            rules
                        )

                    # DB 업데이트 — 공식 룰 발견
                    db.upsert_cve({
                        "id": cve_id,
                        "has_official_rules": True,
                        "rules_snapshot": rules,
                        "last_rule_check_at": now_iso,
                        "updated_at": now_iso
                    })
                else:
                    # 공식 룰 미발견 — 쿨다운 갱신 (7일 후 재확인)
                    db.upsert_cve({
                        "id": cve_id,
                        "last_rule_check_at": now_iso,
                        "updated_at": now_iso
                    })

            except Exception as e:
                logger.error(f"{cve_id} 공식 룰 체크 실패: {e}")
                # 실패 시 쿨다운 1일: last_rule_check_at을 6일 전으로 설정
                # → 7일 쿨다운 기준으로 내일 재시도 가능
                try:
                    fake_past = (datetime.datetime.now(KST) - datetime.timedelta(days=6)).isoformat()
                    db.upsert_cve({
                        "id": cve_id,
                        "last_rule_check_at": fake_past,
                        "updated_at": datetime.datetime.now(KST).isoformat()
                    })
                except Exception:
                    pass
                continue

        logger.info(f"=== 공식 룰 재발견 체크 완료 (발견: {found_count}건) ===")

    except Exception as e:
        logger.error(f"공식 룰 체크 프로세스 실패: {e}")

# ==============================================================================
# [5.5] 에스컬레이션 재평가 스윕 (외부 피드 단독 변화 → 고위험 승격)
# ==============================================================================

def check_for_escalations(collector: Collector, db: ArgusDB, notifier: SlackNotifier) -> None:
    """외부 피드(KEV/EPSS/ExploitDB/Metasploit) 단독 변화로 저위험→고위험 승격되는 CVE 재평가.

    파이프라인은 cvelistV5 커밋(레코드 변경)을 트리거로 재수집한다. 따라서 레코드는 그대로인데
    외부 피드만 바뀐 경우(예: EPSS만 급등, Metasploit 모듈만 신규 공개, KEV 등재가 레코드
    업데이트를 동반하지 않은 경우)에는 그 CVE가 재수집 큐에 안 올라와 에스컬레이션 재알림이
    누락될 수 있다. 이 스윕이 그 사각지대를 메운다.

    2단계로 값싸게 처리한다:
      Phase A (사전필터, 네트워크 0): '현재 저위험' 후보의 최신 외부 신호(KEV 세트 멤버십,
        EPSS 배치, ExploitDB/Metasploit 캐시 인덱스)로 current를 만들어 저장된 last와
        _should_send_alert로 비교 — 승격 트리거가 잡히는 CVE만 추린다.
      Phase B (승격분만): 그 CVE를 process_single_cve로 풀 재처리(레코드 재수집→위협인텔→
        분석→Issue→Slack→저장). 재처리 안에서 최신 신호로 재판정하므로 알림/저장이 일관된다.

    재알림 중복은 없다: 승격이 성공 저장되면 last_alert_state가 갱신돼 다음 스윕에서 current==last가
    되어 재트리거되지 않는다. Groq 소진 등으로 저장 전 실패하면 Slack도 안 나가고(게이트가
    Slack 이전에 조기 반환) last가 그대로라 다음 실행 스윕에서 자연히 재시도된다.
    """
    try:
        logger.info("=== 에스컬레이션 재평가 스윕 시작 ===")
        days = config.PERFORMANCE.get("escalation_sweep_days", 30)
        limit = config.PERFORMANCE.get("escalation_candidate_limit", 300)
        candidates = db.get_escalation_candidates(days=days, limit=limit)
        if not candidates:
            logger.info("에스컬레이션 후보 없음")
            return

        # 외부 피드 최신값 — EPSS만 배치 네트워크(50건/요청), 나머지는 메모리/캐시.
        collector.fetch_epss([r['id'] for r in candidates])

        escalated: List[str] = []
        for record in candidates:
            try:
                cve_id = record['id']
                last = record.get('last_alert_state')
                if not last:
                    continue

                # current = last 복사 후 외부 피드 4개 필드만 최신값으로 덮어씀.
                # 레코드 기반 필드(cvss/cwe/affected/ssvc)는 레코드 미변경이라 last 그대로 둔다
                # → CVSS 상향 트리거는 여기서 안 잡히고(정상: 레코드 변경 경로가 담당) 외부 피드
                #   전이(KEV/EPSS/ExploitDB/Metasploit)만 판정한다.
                current = dict(last)
                # 구버전 state에 cvss/epss 키가 없을 수 있음 → 스칼라 컬럼으로 폴백 (KeyError 방지)
                current.setdefault('cvss', record.get('cvss_score') or 0.0)
                base_epss = last.get('epss')
                if base_epss is None:
                    base_epss = record.get('epss_score') or 0.0
                current['is_kev'] = cve_id in collector.kev_set
                current['epss'] = collector.epss_cache.get(cve_id, base_epss)
                # ExploitDB/Metasploit 신호는 캐시 인덱스 조회 — collector 로직 재사용(네트워크 0)
                probe = {'id': cve_id}
                collector.enrich_cheap_signals(probe)
                current['has_public_exploit'] = probe.get('has_public_exploit') or last.get('has_public_exploit', False)
                current['has_metasploit_module'] = probe.get('has_metasploit_module') or last.get('has_metasploit_module', False)
                # 랜섬웨어 플래그도 KEV 피드에서 오는 값이라 매 실행 최신으로 덮는다
                # (SSVC/CVSS 등 레코드 기반 필드는 위 주석대로 last를 그대로 둔다)
                current['is_kev_ransomware'] = probe.get('is_kev_ransomware', False)

                # 자산 매칭 종류는 저장된 판정을 그대로 쓴다 — 기본값('wildcard')로 두면
                # 등록 자산 CVE가 스윕에서만 비자산으로 취급돼 본 경로와 기준이 갈린다.
                # (미저장 구버전 행은 기존과 동일하게 wildcard로 보수적 판정)
                should, reason, _ = _should_send_alert(
                    current, last, match_type=last.get('match_type') or "wildcard")
                if should:
                    logger.info(f"🔁 {cve_id}: 외부 피드 에스컬레이션 감지 ({reason})")
                    escalated.append(cve_id)
            except Exception as e:
                # 한 레코드의 이상 데이터가 스윕 전체를 중단시키지 않게 격리
                logger.warning(f"{record.get('id', '?')} 에스컬레이션 재평가 실패: {e}")
                continue

        if not escalated:
            logger.info(f"에스컬레이션 후보 {len(candidates)}건 재평가 — 승격 없음")
            return

        max_reprocess = config.PERFORMANCE.get("max_escalation_reprocess", 20)
        to_reprocess = escalated[:max_reprocess]
        if len(escalated) > len(to_reprocess):
            logger.warning(f"에스컬레이션 {len(escalated)}건 중 {len(to_reprocess)}건 재처리, 나머지는 다음 실행 스윕에서")
        logger.info(f"에스컬레이션 {len(to_reprocess)}건 풀 재처리")
        for cve_id in to_reprocess:
            try:
                process_single_cve(cve_id, collector, db, notifier)
            except Exception as e:
                logger.error(f"{cve_id} 에스컬레이션 재처리 실패: {e}")

        logger.info(f"=== 에스컬레이션 재평가 스윕 완료 (승격 감지: {len(escalated)}건, 재처리: {len(to_reprocess)}건) ===")

    except Exception as e:
        logger.error(f"에스컬레이션 스윕 실패: {e}")

# ==============================================================================
# [6] 메인 실행 로직
# ==============================================================================

def _main():
    start_time = time.time()
    logger.info("=" * 60)
    logger.info(f"Argus Phase 1 시작 (Model: {config.MODEL_PHASE_1})")
    logger.info("=" * 60)
    
    # Step 1: 헬스체크
    health = config.health_check()
    if not all(health.values()):
        logger.error(f"헬스체크 실패: {health}")
        return
    logger.info(f"✅ 헬스체크 통과: {health}")
    
    # Step 2: 모듈 초기화
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()

    # 이전 실행들의 일일 요청 수(RPD)를 이어받는다 — 프로세스가 매 실행 새로 뜨는 탓에
    # 카운터가 늘 0에서 시작해 무료 티어 일일 한도를 스스로 못 지키던 문제의 해소.
    # 첫 Gemma 호출(에스컬레이션 스윕 단건 번역)보다 먼저 실행되어야 한다.
    rate_limit_manager.import_rpd_state(read_rpd_state())

    # Step 3: 공식 룰 재발견
    check_for_official_rules()
    
    # Step 4: KEV 및 최신 CVE 수집 (워터마크 기반 — 누락 0)
    collector.fetch_kev()
    collector.fetch_vulncheck_kev()

    # Step 4.5: 에스컬레이션 재평가 스윕 — 레코드 미변경으로 재수집 큐에 안 올라오는 저위험 CVE의
    # 외부 피드(KEV/EPSS/ExploitDB/Metasploit) 단독 변화 승격을 메운다. KEV 세트가 로드된 직후
    # 실행해 승격 재알림이 신규 저위험 백로그보다 우선 Groq 예산을 확보하고 타임아웃 전에 완주하게 한다.
    check_for_escalations(collector, db, notifier)

    # 소프트 데드라인 — Actions timeout(45분)에 killed 되면 워터마크를 못 써 다음 실행이
    # 수집을 통째로 반복한다. 그 전에 스스로 잔여 작업을 failed로 남기고(워터마크가 붙잡음)
    # 워터마크 저장·요약까지 '항상 깨끗하게' 끝내는 것이 전진의 핵심.
    soft_deadline_ts = start_time + config.PERFORMANCE.get("soft_deadline_minutes", 38) * 60

    def _over_deadline() -> bool:
        return time.time() > soft_deadline_ts

    run_start_utc = datetime.datetime.now(datetime.timezone.utc)
    watermark = read_watermark()
    # 경계 커밋을 놓치지 않도록 소량 겹침(overlap) — 중복은 DB dedup이 흡수
    since_dt = watermark - datetime.timedelta(minutes=5)
    # 초장기 공백(수일+) 캐치업 상한: 한 실행의 조회 창을 최대 12시간으로 제한.
    # 무제한 조회는 커밋 상세 호출 폭증 → 타임아웃 → 워터마크 미저장 → 같은 작업
    # 반복(진행 불가)으로 이어질 수 있다. 창 밖 커밋은 다음 실행이 전진된 워터마크에서
    # 이어서 수집하므로 누락은 없다 (실행당 12h씩 따라잡음).
    catchup_horizon = watermark + datetime.timedelta(hours=12)
    until_dt = catchup_horizon if catchup_horizon < run_start_utc else None
    fetched = collector.fetch_cves_since(since_dt, db=db, until_dt=until_dt,
                                         deadline_ts=soft_deadline_ts)

    if not fetched:
        # 창 내 신규 커밋 없음 → 창 끝까지만 전진 (창 이후 커밋은 다음 실행이 수집)
        write_watermark(min(catchup_horizon, run_start_utc),
                        rpd=rate_limit_manager.export_rpd_state())
        logger.info("처리할 CVE 없음 (워터마크 전진)")
        return

    # Step 5: 신규만 처리 대상. 우선순위 = KEV(실제 악용 확인) 먼저, 그 안에서는 커밋 오래된 순(FIFO).
    # KEV 멤버십은 메모리 세트라 값싸게 판별 가능 → 백로그가 커도 알려진 악용 취약점을 먼저 처리한다.
    # (CVSS 기반 완전 정렬은 CVE별 fetch가 필요해 백로그 전체엔 비쌈 → KEV 우선으로 핵심만 앞당김.)
    new_items = [c for c in fetched if c['is_new']]
    # 격리(quarantine) 중인 CVE는 이번 실행에서 건드리지 않는다 — 아래 워터마크 계산 주석 참조.
    # 격리 유효기간이 지난 건은 active_quarantine이 자동 제외 → 다시 정상 처리 대상이 된다.
    fail_counts, quarantined = read_failure_state()
    quarantine_hours = config.PERFORMANCE.get("quarantine_retry_hours", 24)
    held = active_quarantine(quarantined, quarantine_hours)
    if held:
        blocked = [c['cve_id'] for c in new_items if c['cve_id'] in held]
        if blocked:
            logger.warning(f"⛔ 격리 중 {len(blocked)}건 이번 실행 제외 (예: {blocked[:3]}) — "
                           f"{quarantine_hours}h 후 자동 재시도")
        new_items = [c for c in new_items if c['cve_id'] not in held]
    kev_set = collector.kev_set
    new_items.sort(key=lambda c: (0 if c['cve_id'] in kev_set else 1, c['commit_ts']))
    max_per_run = config.PERFORMANCE.get("max_cves_per_run", 15)
    to_process = new_items[:max_per_run]
    deferred = new_items[max_per_run:]
    if deferred:
        logger.warning(f"신규 {len(new_items)}건 중 {len(to_process)}건 처리, {len(deferred)}건 다음 실행으로 이월(워터마크 뒤에 보존)")
        # 이월분의 심각도 분포를 표본으로 추정해 남긴다 — Medium/Low가 대부분이면
        # (비자산은 마커, 에스컬레이션 승격 시 재알림) 백로그를 기다려도 안전함을 즉시 확인.
        _log_deferred_severity_estimate(deferred, collector, soft_deadline_ts)

    target_cve_ids = [c['cve_id'] for c in to_process]

    # Step 5.5: 신호 드리프트 대조 — 신호 소스(KEV/EPSS) 쪽에서 역방향으로 훑어
    # DB의 저장 상태와 어긋난 CVE를 큐 앞에 추가한다. DB에서 후보를 고르는 방식은
    # 그 선정 조건(CVSS·기간·건수·마커 여부)이 그대로 사각지대가 되므로 방향을 뒤집었다.
    # 워터마크 흐름(to_process/deferred)과 별개라 워터마크 계산에는 불포함 —
    # 실패해도 다음 실행에서 같은 대조가 다시 잡는다(신호가 소스에 남아 있는 한).
    drift_cap = config.PERFORMANCE.get("max_drift_candidates", 60)
    seen = set(target_cve_ids)
    kev_extra = _kev_drift_candidates(collector, db, exclude=seen)[:drift_cap]
    seen.update(kev_extra)
    epss_extra = _epss_surge_candidates(collector, db, exclude=seen)[:drift_cap]
    signal_extra = kev_extra + epss_extra
    target_cve_ids = signal_extra + target_cve_ids

    # Step 6: EPSS 수집
    collector.fetch_epss(target_cve_ids)
    logger.info(f"분석 대상: {len(target_cve_ids)}건 "
                f"(신호 드리프트 {len(signal_extra)}건: KEV {len(kev_extra)} · EPSS {len(epss_extra)})")

    # Step 7: CVE 처리 — 3단계 파이프라인
    #   Phase A(병렬): 수집·분류·위협인텔 / B(배치): 한국어 번역 / C(병렬): Issue·Slack·저장
    # 번역을 CVE마다 개별 호출하면 Gemma RPM 15(4초 간격)에 직렬화되어 실행당 8분+를 먹고,
    # 풀가동 시 일 2,880콜로 RPD 1,500을 초과한다 → 배치(10건/호출)로 시간·예산 모두 1/10.
    status_by_id = {}
    max_workers = config.PERFORMANCE["max_workers"]
    batch_size = config.PERFORMANCE.get("translation_batch_size", 10)
    logger.info(f"처리 시작 (워커: {max_workers}명, 번역 배치 {batch_size}건/호출)")

    # Phase A: 수집·분류 (병렬) — 데드라인 도달 시 잔여 취소(미기록 → 아래 안전망이 failed 처리)
    prepared = []
    marker_skips = 0   # 비자산 저위험 마커 처리 수 (백로그 해소 관측용)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(prepare_single_cve, cid, collector, db): cid for cid in target_cve_ids}
        for future in as_completed(futures):
            if _over_deadline():
                executor.shutdown(wait=False, cancel_futures=True)
                logger.warning("⏰ 시간 예산 도달 — Phase A 잔여 취소 (다음 실행에서 재처리)")
                break
            cid = futures[future]
            try:
                prep = future.result() or {}
            except Exception as e:
                logger.error(f"{cid} 준비 중 예외 발생: {e}")
                status_by_id[cid] = "failed"
                continue
            if prep.get("skipped_low_wildcard"):
                marker_skips += 1
            if prep.get("stage") == "ready":
                prepared.append(prep)
            else:
                status_by_id[cid] = prep.get("status", "failed")

    # 분류 요약 — "신규 N건 중 무엇이 몇 건인지" 실행마다 즉시 보이게
    alert_cnt = sum(1 for p in prepared if p["should_alert"])
    tracked_high = sum(1 for p in prepared if not p["should_alert"] and p.get("tier") == "high")
    tracked_low = len(prepared) - alert_cnt - tracked_high
    updated_cnt = sum(1 for s in status_by_id.values() if s == "handled") - marker_skips
    logger.info(
        f"📊 분류: 대상 {len(target_cve_ids)}건 → 알림(Critical/자산High) {alert_cnt} / "
        f"High 추적 {tracked_high} / 자산저위험 추적 {tracked_low} / "
        f"비자산 마커 {marker_skips} / 기존갱신·스킵 {max(updated_cnt, 0)}"
    )

    if _over_deadline():
        # 번역/완성 없이 종료 — prepared 전부 미완료(failed) 처리해 다음 실행에서 온전히 재처리
        logger.warning(f"⏰ 시간 예산 도달 — 준비된 {len(prepared)}건 포함 잔여분 다음 실행으로")
        prepared = []
    else:
        # Phase B: 일괄 번역 (Gemma 호출 = ceil(n/배치)) — 데드라인을 Phase C 예약분만큼
        # 앞당겨 전달. 번역이 전체 예산을 소진하면 Phase C(Issue·Slack·저장)가 0초로 시작해
        # Critical 알림까지 통째로 다음 실행으로 밀리는 기아가 발생했던 것의 방지책.
        tr_items = [{"id": p["cve_id"], "title": p["current_state"]["title"],
                     "description": p["current_state"]["description"]} for p in prepared]
        high_risk_ids = {p["cve_id"] for p in prepared if p["should_alert"]}
        phase_c_reserve = config.PERFORMANCE.get("phase_c_reserve_minutes", 8) * 60
        translations = generate_korean_summaries_batch(tr_items, high_risk_ids,
                                                       deadline_ts=soft_deadline_ts - phase_c_reserve)

        # Phase C: 완성 — Issue/Slack/저장 (병렬).
        # 고위험(알림 대상)을 먼저 제출해 데드라인이 닥쳐도 핵심 알림부터 완료되게 한다.
        prepared.sort(key=lambda p: (0 if p["should_alert"] else 1))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(finalize_single_cve, p, translations.get(p["cve_id"]),
                                db, notifier): p["cve_id"]
                for p in prepared
            }
            for future in as_completed(futures):
                if _over_deadline():
                    executor.shutdown(wait=False, cancel_futures=True)
                    logger.warning("⏰ 시간 예산 도달 — Phase C 미시작 잔여 취소 (실행 중 건은 완료 후 기록)")
                    break
                cid = futures[future]
                try:
                    result = future.result() or {}
                    status_by_id[cid] = result.get("status", "failed")
                except Exception as e:
                    logger.error(f"{cid} 처리 중 예외 발생: {e}")
                    status_by_id[cid] = "failed"

            # 드레인: 데드라인 break 후에도 '이미 실행 중'인 건은 취소 불가 → 완료를 기다려
            # 실제 결과를 기록한다. (기존엔 Issue/DB 저장까지 끝난 건도 안전망이 failed로
            # 오기록 → "알림 0건" 오표기 + 다음 실행 불필요 재수집. with 종료가 어차피
            # 실행 중 스레드를 join하므로 추가 대기 비용은 없음.)
            # 주의: as_completed 루프로 드레인하면 안 됨 — shutdown(cancel_futures=True)의
            # cancel()은 waiter를 깨우지 않아 루프가 영원히 블록된다(검증됨).
            for future, cid in futures.items():
                if cid in status_by_id:
                    continue  # 루프에서 이미 기록됨
                if future.cancelled():
                    status_by_id[cid] = "failed"  # 미시작 취소분 → 워터마크가 붙잡아 재처리
                    continue
                try:
                    result = future.result() or {}
                    status_by_id[cid] = result.get("status", "failed")
                except CancelledError:
                    status_by_id[cid] = "failed"
                except Exception as e:
                    logger.error(f"{cid} 처리 중 예외 발생: {e}")
                    status_by_id[cid] = "failed"

    # 안전망: 상태가 기록되지 않은 처리 대상(취소·미완료)은 전부 failed —
    # 워터마크 계산이 이들을 '처리됨'으로 오인해 건너뛰면 영구 누락이므로 반드시 필요.
    for c in to_process:
        status_by_id.setdefault(c['cve_id'], "failed")

    # Step 8: 워터마크 전진 계산 (누락 0의 핵심)
    #
    # 미처리(unhandled) = 실패한 처리분 + 상한으로 이월된 분. 이들의 최소 커밋시각 앞까지만 전진.
    # 단, '영구 실패' 레코드는 반드시 격리해야 한다 — 매번 실패하는 CVE 1건이 있으면
    # 워터마크가 그 시각에 영구 고정되고, 조회 창(watermark+12h)도 함께 얼어붙어
    # 그 이후의 신규 CVE를 영원히 못 본다(파이프라인 전면 정지). 연속 N회 실패한 CVE는
    # 워터마크 계산에서 제외(격리)해 전진시키고, quarantine_retry_hours 후 자동 재시도한다.
    max_fail = config.PERFORMANCE.get("max_consecutive_failures", 3)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    newly_quarantined = []
    for c in to_process:
        cid = c['cve_id']
        st = status_by_id.get(cid)
        if st == 'failed':
            fail_counts[cid] = fail_counts.get(cid, 0) + 1
            if fail_counts[cid] >= max_fail and cid not in quarantined:
                quarantined[cid] = now_iso
                newly_quarantined.append(cid)
        elif st in ('success', 'handled'):
            # 성공 → 실패 이력·격리 해제 (일시 장애가 회복된 경우)
            fail_counts.pop(cid, None)
            quarantined.pop(cid, None)

    if newly_quarantined:
        logger.error(
            f"⛔ 연속 {max_fail}회 실패로 격리: {len(newly_quarantined)}건 {newly_quarantined[:5]} — "
            f"워터마크 전진을 위해 제외 (파이프라인 정지 방지). "
            f"{config.PERFORMANCE.get('quarantine_retry_hours', 24)}h 후 자동 재시도"
        )
        notifier.send_pipeline_warning(
            "⛔ CVE 격리 발생",
            f"연속 {max_fail}회 처리 실패로 {len(newly_quarantined)}건을 격리했습니다. "
            f"워터마크 정지를 막기 위한 조치이며 자동 재시도됩니다.\n"
            f"`{', '.join(newly_quarantined[:10])}`"
        )

    # 격리분은 unhandled에서 제외 — 이것이 워터마크를 전진시켜 파이프라인을 살린다
    held_now = set(quarantined)
    unhandled_ts = [c['commit_ts'] for c in to_process
                    if status_by_id.get(c['cve_id']) == 'failed' and c['cve_id'] not in held_now]
    unhandled_ts += [c['commit_ts'] for c in deferred]
    if unhandled_ts:
        new_watermark = min(unhandled_ts)  # 이 시각 이후는 다음 실행에서 재수집
    else:
        # 전부 처리됨 → 이번에 본 가장 최신 커밋 시각까지 전진
        new_watermark = max(c['commit_ts'] for c in fetched)

    # 상태 파일 비대화 방지 — 격리 유효기간이 한참 지난 항목은 정리(재시도 후 성공 시 삭제됨)
    stale_cut = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)
    quarantined = {k: v for k, v in quarantined.items()
                   if _iso_after(v, stale_cut)}
    fail_counts = {k: v for k, v in fail_counts.items() if k in held_now or v > 0}
    write_watermark(new_watermark, failures=fail_counts, quarantined=quarantined,
                    rpd=rate_limit_manager.export_rpd_state())

    # 워터마크 저장 이후에 백필 — 여기서 무슨 일이 나도 이번 회차의 전진은 이미 확정이다
    backfill_translations(db, soft_deadline_ts)
    # 백필이 소비한 호출까지 반영 (워터마크는 그대로 두고 사용량만 갱신)
    write_rpd_state(rate_limit_manager.export_rpd_state())

    success_count = sum(1 for s in status_by_id.values() if s == 'success')

    # 분석 티어 소진 경고 — 주력(Gemini) 기준으로 본다
    if rate_limit_manager.is_rpd_exhausted("gemini_analysis"):
        if rate_limit_manager.active_groq_model(config.GROQ_MODELS) is None:
            logger.warning("🚫 분석 티어 전부(Gemini 주력 + Groq 비상) 소진 → "
                           "일부 고위험 CVE 보류, 다음 실행에서 자동 재처리")
        else:
            logger.warning("⚠️ Gemini 주력 RPD 소진 → 분석이 Groq 비상 티어로 수행됨")

    # Step 9: Slack 배치 요약 전송 (High 추적 건수 포함 — Issue 없이도 규모는 파악되게)
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    dashboard_url = f"https://{repo.split('/')[0].lower()}.github.io/{repo.split('/')[1]}/" if '/' in repo else None
    notifier.send_batch_summary(dashboard_url=dashboard_url, tracked_high=tracked_high)

    # Step 10: 결과 요약
    elapsed = time.time() - start_time
    logger.info("=" * 60)
    logger.info(f"처리 완료: 알림 {success_count}건 / 처리 {len(target_cve_ids)}건 "
                f"(비자산 저위험 마커 {marker_skips}건) / 이월 {len(deferred)}건")
    logger.info(f"워터마크: {new_watermark.isoformat()}")
    logger.info(f"소요 시간: {elapsed:.1f}초")
    logger.info("=" * 60)

    # Step 11: Rate Limit 사용 요약
    rate_limit_manager.print_summary()


def _notify_pipeline_failure(error: Exception) -> None:
    """파이프라인 최상위 실패를 Slack에 알림 (알림 자체의 실패는 무시하고 넘어감)"""
    try:
        webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        if not webhook_url:
            return
        payload = {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": "🔴 Argus 파이프라인 실패"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```{type(error).__name__}: {error}```"}},
            ]
        }
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception:
        pass


def main():
    try:
        _main()
    except Exception as e:
        logger.error(f"파이프라인 최상위 실패: {e}", exc_info=True)
        _notify_pipeline_failure(e)


if __name__ == "__main__":
    main()