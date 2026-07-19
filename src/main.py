import os
import re
import json
import datetime
import time
import requests
import pytz
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
from google import genai
from google.genai import types
from logger import logger
from config import config
from collector import Collector, read_watermark, write_watermark
from database import ArgusDB
from notifier import SlackNotifier
from analyzer import Analyzer
from rule_manager import RuleManager
from rate_limiter import rate_limit_manager

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

def is_target_asset(cve_data: Dict, cve_id: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """자산 매칭 판정. 반환: (매칭 여부, 매칭 근거, 매칭 종류).

    매칭 종류(match_type)가 자산 기준 티어링의 핵심이다:
      "asset"    — 등록된 구체 자산 룰에 매칭 → 저위험도 추적(번역+대시보드)
      "wildcard" — 구체 룰엔 안 맞고 */*(전체 감시)로만 매칭 → 고위험/에스컬레이션만 수신,
                   신규 저위험은 마커만 저장(대시보드 비노출)
      None       — 어느 룰에도 안 맞음 → 처리 안 함
    구체 룰을 전부 먼저 검사하고, 실패했을 때만 wildcard로 분류한다."""
    # 벤더/제품 표기 차이(언더스코어 vs 공백)를 흡수해 매칭 누락 방지
    def _norm(s: str) -> str:
        return s.lower().replace('_', ' ').strip()

    has_wildcard = False
    for target in config.get_target_assets():
        t_vendor = _norm(target.get('vendor', ''))
        t_product = _norm(target.get('product', ''))

        # 전체 감시 룰은 기억만 하고 구체 룰부터 검사 (asset 판정이 우선)
        if t_vendor == "*" and t_product == "*":
            has_wildcard = True
            continue

        # 1차: affected 필드의 구조화된 vendor/product 매칭
        for affected in cve_data.get('affected', []):
            a_vendor = _norm(affected.get('vendor', ''))
            a_product = _norm(affected.get('product', ''))

            # vendor가 N/A, Unknown이면 건너뛰기 (2·3차에서 확인)
            if a_vendor in ('', 'unknown', 'n/a'):
                continue

            vendor_match = (t_vendor in a_vendor) or (a_vendor in t_vendor)
            product_match = (t_product == "*") or (t_product in a_product) or (a_product in t_product)

            if vendor_match and product_match:
                return True, f"Matched (affected): {a_vendor}/{a_product}", "asset"

        # 2차: NVD CPE의 vendor/product 매칭 (affected가 비거나 불명일 때 보완)
        for cpe in cve_data.get('nvd_cpe', []):
            parts = cpe.split(':')
            if len(parts) < 5:
                continue
            c_vendor, c_product = _norm(parts[3]), _norm(parts[4])
            if c_vendor in ('', '*', '-'):
                continue
            vendor_match = (t_vendor in c_vendor) or (c_vendor in t_vendor)
            product_match = (t_product == "*") or (t_product in c_product) or (c_product in t_product)
            if vendor_match and product_match:
                return True, f"Matched (NVD CPE): {c_vendor}/{c_product}", "asset"

        # 3차(보조): description 텍스트 매칭
        desc_lower = cve_data.get('description', '').lower()
        if desc_lower and t_vendor in desc_lower and (t_product == "*" or t_product in desc_lower):
            return True, f"Matched (description): {t_vendor}/{t_product}", "asset"

    if has_wildcard:
        return True, "All Assets (*)", "wildcard"
    return False, None, None

def _recent_kev_missing(collector: Collector, db: ArgusDB, exclude: set, days: int = 14) -> List[str]:
    """최근 N일 내 KEV 등재분 중 DB에 없고 이번 처리분에도 없는 CVE 목록 (gap-filler).

    비자산 저위험은 저장하지 않으므로(마커도 30일 후 삭제) 에스컬레이션 스윕(DB 기반)이
    못 본다. KEV 등재는 '실제 악용 확인'이라 놓치면 안 되는 1급 신호 → 매 실행 이미 받는
    KEV 목록의 dateAdded로 최근 등재분을 골라 DB 미보유분을 직접 처리 큐에 넣는다.
    이들은 is_kev=True → 신규 고위험(T1)으로 자연 처리된다."""
    cutoff = (datetime.datetime.now(datetime.timezone.utc)
              - datetime.timedelta(days=days)).strftime('%Y-%m-%d')
    recent = [cid for cid, added in collector.kev_date_added.items()
              if added and added >= cutoff and cid not in exclude]
    if not recent:
        return []
    existing = db.batch_get_content_hashes(recent)
    missing = [cid for cid in recent if cid not in existing]
    if missing:
        logger.info(f"🚨 KEV gap-filler: 최근 {days}일 등재 {len(recent)}건 중 미보유 {len(missing)}건 추가 수집")
    return missing


def _needs_cpe_for_matching(cve_data: Dict) -> bool:
    """자산 매칭에 NVD CPE 선제 조회가 필요한지 판단.

    전체 감시(*/*)면 매칭이 항상 참이라 불필요. 특정 자산 감시인데 CVE의 affected에
    유효한 벤더가 하나도 없으면(Unknown/N-A), NVD CPE 없이는 벤더 매칭이 불가능해
    감시 대상 CVE를 놓칠 수 있다 → 이때만 True (NVD 1회 조회 비용 발생)."""
    targets = config.get_target_assets()
    if any(t.get('vendor') == '*' and t.get('product') == '*' for t in targets):
        return False
    return not any(
        a.get('vendor', '').lower() not in ('', 'unknown', 'n/a')
        for a in cve_data.get('affected', [])
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
            rate_limit_manager.check_and_wait("gemini")
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

            return title_ko, desc_ko

        except Exception as e:
            msg = str(e)
            if retry_on_transient and _is_transient_gemini_error(msg) and attempt < max_attempts:
                wait = 2 * attempt  # 2s, 4s
                logger.warning(f"번역 일시오류({attempt}/{max_attempts}): {e} → {wait}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"번역 실패: {e}, 원본 사용")
            return fallback

    return fallback


def _is_transient_gemini_error(msg: str) -> bool:
    """Gemma 일시 서버 오류(재시도 가치 있음) 판별.
    상태 코드는 단어 경계로 매칭 — "limit: 1500" 같은 숫자에 "500"이 오탐되지 않게."""
    return bool(re.search(r'\b(500|503)\b', msg)) or any(t in msg for t in (
        "INTERNAL", "UNAVAILABLE", "high demand", "overloaded", "try again"
    ))


def generate_korean_summaries_batch(items: List[Dict], high_risk_ids: set,
                                    deadline_ts: Optional[float] = None) -> Dict[str, Tuple[str, str]]:
    """여러 CVE의 제목/설명을 Gemma 호출 1번에 N건씩 묶어 일괄 번역.

    개별 호출은 Gemma RPM 15(호출당 4초 간격)에 묶여 실행당 번역만 8분+이 걸리고,
    풀가동(120건×24회=2,880콜/일)이면 RPD 1,500을 초과해 오후부터 번역이 영문 폴백으로
    떨어진다. 10건/호출 배치면 시간·일일 예산이 모두 1/10로 줄어 처리 상한을 올릴 수 있다.

    폴백 정책(기존 단건과 동일 원칙): 청크 호출이 최종 실패하면 고위험(high_risk_ids)만
    단건 재시도로 한글화를 보장하고, 저위험은 즉시 영문 폴백.
    반환: cve_id → (title_ko, desc_ko). 모든 입력 id에 대해 값이 존재한다.
    """
    results: Dict[str, Tuple[str, str]] = {}
    if not items:
        return results

    batch_size = config.PERFORMANCE.get("translation_batch_size", 10)
    total_chunks = (len(items) + batch_size - 1) // batch_size
    logger.info(f"일괄 번역: {len(items)}건 → Gemma {total_chunks}회 호출 (배치 {batch_size}건)")
    started = time.time()
    deadline_hit = False

    for chunk_no, i in enumerate(range(0, len(items), batch_size), 1):
        chunk = items[i:i + batch_size]
        # 시간 예산 도달 → 잔여 청크는 영문 폴백 (번역이 실행 전체를 볼모로 잡지 않게).
        # 알림 대상(high_risk_ids)만 단건 재시도로 한글화를 지키고, 나머지는 즉시 영문.
        if deadline_ts is not None and time.time() > deadline_ts:
            if not deadline_hit:
                logger.warning(f"⏰ 번역 시간 예산 도달 — 잔여 {total_chunks - chunk_no + 1}청크 영문 폴백")
                deadline_hit = True
            parsed = None
        else:
            chunk_has_high = any(it['id'] in high_risk_ids for it in chunk)
            parsed = _translate_chunk(chunk, retry_on_transient=chunk_has_high)
            if chunk_no % 5 == 0 or chunk_no == total_chunks:
                logger.info(f"일괄 번역 진행: {chunk_no}/{total_chunks} 청크 ({time.time() - started:.0f}초 경과)")
        if parsed is not None:
            results.update(parsed)
            continue
        # 청크 실패/예산 초과 → 알림 대상만 단건 재시도(한글 보장), 나머지는 영문 폴백
        for it in chunk:
            if it['id'] in high_risk_ids and not deadline_hit:
                results[it['id']] = generate_korean_summary(
                    {"title": it['title'], "description": it['description']},
                    retry_on_transient=True)
            else:
                results[it['id']] = (it['title'], (it['description'] or '')[:200])
    return results


def _translate_chunk(chunk: List[Dict], retry_on_transient: bool) -> Optional[Dict[str, Tuple[str, str]]]:
    """청크(≤batch_size건) 1회 Gemma 호출 번역. 성공 시 id→(제목,요약) dict, 실패 시 None.
    응답 JSON에서 누락된 항목은 영문 폴백으로 채워 반환값은 항상 청크 전체를 커버한다."""
    # 입력 500자·출력 2줄 요약으로 제한 — 배치당 생성 토큰을 줄여 호출당 소요를 절반 이하로
    # (관측: 출력이 크면 배치당 ~60초 → 40청크에 40분, 실행 타임아웃의 주범이었음)
    numbered = "\n".join(
        f"{n}. Title: {it['title']} / Desc: {(it['description'] or '')[:500]}"
        for n, it in enumerate(chunk, 1)
    )
    prompt = f"""
Task: For EACH numbered CVE below, translate the Title into Korean and summarize the Description into Korean (max 2 short lines each).
Keep technical terms in English or Korean transliteration (e.g., "버퍼 오버플로우", "SQL 인젝션"). Do NOT translate them literally.
Return ONLY a JSON array with exactly {len(chunk)} objects, same order as inputs, no other text:
[{{"n": 1, "title_ko": "...", "desc_ko": "..."}}, ...]

{numbered}
"""
    max_attempts = 3 if retry_on_transient else 1
    for attempt in range(1, max_attempts + 1):
        try:
            rate_limit_manager.check_and_wait("gemini")
            response = gemini_client.models.generate_content(
                model=config.MODEL_PHASE_0,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=2048,  # 10건 × 제목+2줄 요약 상한 — 생성 속도 확보
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
                    return None
                arr = json.loads(m.group())

            if not isinstance(arr, list):
                return None
            by_n = {int(o.get('n', 0)): o for o in arr if isinstance(o, dict)}
            out: Dict[str, Tuple[str, str]] = {}
            for n, it in enumerate(chunk, 1):
                o = by_n.get(n, {})
                title_ko = (o.get('title_ko') or '').strip() or it['title']
                desc_ko = (o.get('desc_ko') or '').strip() or (it['description'] or '')[:200]
                out[it['id']] = (title_ko, desc_ko)
            return out

        except Exception as e:
            msg = str(e)
            if retry_on_transient and _is_transient_gemini_error(msg) and attempt < max_attempts:
                wait = 2 * attempt
                logger.warning(f"일괄 번역 일시오류({attempt}/{max_attempts}): {e} → {wait}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"일괄 번역 청크 실패: {e}")
            return None
    return None

# ==============================================================================
# [3] GitHub Issue 생성/업데이트
# ==============================================================================

def _rule_license_note(rule_info: Dict) -> str:
    """공식 룰 재게시 시 출처·author·라이선스 고지 보존 (불변 원칙 8-①)"""
    lic = rule_info.get('license')
    if not lic:
        return ""
    return f"\n> **License:** {lic} — 원 룰의 출처·author·라이선스 고지를 보존합니다.\n"

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
        body = _build_issue_body(cve_data, reason, analysis, rules, has_official)
        
        # Step 5: GitHub API 호출
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}",
            "body": body,
            "labels": ["security", "cve"]
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        
        issue_url = response.json().get("html_url")
        logger.info(f"GitHub Issue 생성 성공: {issue_url}")
        
        return issue_url, {"has_official": has_official, "rules": rules}
        
    except Exception as e:
        logger.error(f"GitHub Issue 생성 실패: {e}")
        return None, None

def _build_issue_body(cve_data: Dict, reason: str, analysis: Dict, rules: Dict, has_official: bool) -> str:
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
    threat_signals = ("## 🧨 위협 신호\n" + "\n".join(signal_lines) + "\n") if signal_lines else ""

    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    
    # 영향받는 자산 테이블
    affected_rows = ""
    for item in cve_data.get('affected', []):
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} |\n"
    if not affected_rows:
        affected_rows = "| - | - | - |"
    
    # 대응 방안
    mitigation_list = "\n".join([f"- {m}" for m in analysis.get('mitigation', [])])
    
    # 참고 자료 (Exploit-DB는 PoC 원문 대신 링크만 게시 — 불변 원칙 8-②)
    ref_items = list(cve_data['references'])
    if cve_data.get('_exploit_db_url'):
        ref_items.append(f"{cve_data['_exploit_db_url']} (Exploit-DB PoC)")
    ref_list = "\n".join([f"- {r}" for r in ref_items])

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
    
    body = f"""# 🛡️ {cve_data['title_ko']}

> **탐지 일시:** {now_kst}
> **탐지 사유:** {reason}

{badges}
**취약점 유형 (CWE):** {cwe_str}

{threat_signals}
## 📦 영향 받는 자산 (벤더 / 제품 / 버전)
| 벤더 | 제품 | 버전 |
| :--- | :--- | :--- |
{affected_rows}

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

{rules_section}

## 🔗 참고 자료
{ref_list}
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

        if raw_data.get('state') != 'PUBLISHED':
            logger.debug(f"{cve_id}: PUBLISHED 상태 아님, 건너뜀")
            return {"cve_id": cve_id, "status": "handled", "stage": "done"}

        # Step 2: 자산 필터링 (affected vendor/product 우선, NVD CPE 보조, description 보조)
        # 특정 자산 감시(*/* 아님) + CVE에 유효 벤더 없음이면 NVD CPE를 선제 조회해 매칭
        # 소스를 확보한다(자산 매칭 누락 방지). 전체 감시(*/*)에서는 호출 안 함(비용 0).
        if _needs_cpe_for_matching(raw_data):
            collector.enrich_from_nvd(raw_data)
        is_target, match_info, match_type = is_target_asset(raw_data, cve_id)
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
            # P5 데이터 소스 확대 신호
            "ssvc": raw_data.get('ssvc', {}),
            "ssvc_exploitation": (raw_data.get('ssvc') or {}).get('exploitation'),
            "has_public_exploit": raw_data.get('has_public_exploit', False),
            "has_metasploit_module": raw_data.get('has_metasploit_module', False),
            "metasploit_modules": raw_data.get('metasploit_modules', []),
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
                        collector: Collector, db: ArgusDB, notifier: SlackNotifier) -> Dict:
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
            # 분석 3티어(gpt-oss/qwen + Gemini 비상) 전부 소진 시에만 Issue 보류.
            # Groq만 소진이면 Gemini 비상 티어로 분석해 알림 지연 없이 진행한다.
            # 보류 시 Slack/DB저장 없이 failed로 반환해 워터마크가 붙잡고 다음 실행에서 완전 재처리
            # (Slack 미발송 → 중복알림 없음, content_hash 미저장 → 재수집됨 → 누락 없음).
            if (rate_limit_manager.active_groq_model(config.GROQ_MODELS) is None
                    and rate_limit_manager.is_rpd_exhausted("gemini_analysis")):
                logger.warning(f"⚠️ {cve_id}: 분석 전 티어(Groq+Gemini) 소진 → Issue 보류(다음 실행 재처리)")
                return {"cve_id": cve_id, "status": "failed"}
            report_url, rules_info = create_github_issue(current_state, alert_reason)

        # Step 7: Slack 알림 (알림 대상만 — 저위험 신규는 발송 안 함)
        if should_alert:
            notifier.send_alert(current_state, alert_reason, report_url)

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
    return finalize_single_cve(prep, translation, collector, db, notifier)

def _risk_tier(current: Dict) -> str:
    """위험 3단 티어. 실무 유입에서 CVSS 7점대는 하루 수백 건(CISA ADP가 무점수 CVE에
    7.x를 일괄 부여)이라, '진짜 긴급'과 'CVSS만 높음'을 분리해야 알림이 의미를 가진다.

    critical — 실제 악용/무기화 신호 또는 최상위 심각도. 풀 알림(Issue+AI분석+Slack).
    high     — CVSS 7~8.9 단독(다른 신호 없음). 번역+대시보드 추적 + Slack 요약 건수만.
               (자산 등록 CVE는 high도 풀 알림 — 실제 대응 대상이므로.)
    low      — 그 외. 자산이면 추적, 비자산이면 마커.
    """
    if (current['is_kev']
            or current.get('has_metasploit_module')
            or current.get('ssvc_exploitation') == 'active'
            or current.get('epss', 0.0) >= 0.1
            or current['cvss'] >= 9.0):
        return "critical"
    if current['cvss'] >= 7.0:
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

    # EPSS 급증 (≥0.1 도달 = critical 승격)
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

        candidates = db.get_rule_recheck_candidates()

        if not candidates:
            logger.info("재확인 대상 없음")
            return

        # 배치 제한: config 기반 (2시간마다 실행 × 10건 = 하루 120건 처리 가능)
        max_recheck = config.PERFORMANCE.get("max_rule_recheck", 10)
        if len(candidates) > max_recheck:
            logger.info(f"재확인 대상: {len(candidates)}건 중 {max_recheck}건 처리 (우선순위 기반)")
            candidates = candidates[:max_recheck]
        else:
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

                    # Slack 알림 (보존정책으로 last_alert_state가 null일 수 있음 → or 폴백)
                    title_ko = (record.get('last_alert_state') or {}).get('title_ko', cve_id)
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

                should, reason, _ = _should_send_alert(current, last)
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
        write_watermark(min(catchup_horizon, run_start_utc))
        logger.info("처리할 CVE 없음 (워터마크 전진)")
        return

    # Step 5: 신규만 처리 대상. 우선순위 = KEV(실제 악용 확인) 먼저, 그 안에서는 커밋 오래된 순(FIFO).
    # KEV 멤버십은 메모리 세트라 값싸게 판별 가능 → 백로그가 커도 알려진 악용 취약점을 먼저 처리한다.
    # (CVSS 기반 완전 정렬은 CVE별 fetch가 필요해 백로그 전체엔 비쌈 → KEV 우선으로 핵심만 앞당김.)
    new_items = [c for c in fetched if c['is_new']]
    kev_set = collector.kev_set
    new_items.sort(key=lambda c: (0 if c['cve_id'] in kev_set else 1, c['commit_ts']))
    max_per_run = config.PERFORMANCE.get("max_cves_per_run", 15)
    to_process = new_items[:max_per_run]
    deferred = new_items[max_per_run:]
    if deferred:
        logger.warning(f"신규 {len(new_items)}건 중 {len(to_process)}건 처리, {len(deferred)}건 다음 실행으로 이월(워터마크 뒤에 보존)")

    target_cve_ids = [c['cve_id'] for c in to_process]

    # Step 5.5: KEV gap-filler — 최근 등재 KEV 중 DB 미보유분을 큐 앞에 추가.
    # 워터마크 흐름(to_process/deferred)과 별개라 워터마크 계산에는 불포함 —
    # 실패해도 다음 실행의 gap-filler가 다시 잡는다(KEV 목록에 남아 있는 한).
    kev_extra = _recent_kev_missing(collector, db, exclude=set(target_cve_ids))
    target_cve_ids = kev_extra + target_cve_ids

    # Step 6: EPSS 수집
    collector.fetch_epss(target_cve_ids)
    logger.info(f"분석 대상: {len(target_cve_ids)}건 (KEV gap-filler {len(kev_extra)}건 포함)")

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
        # Phase B: 일괄 번역 (Gemma 호출 = ceil(n/배치)) — 시간 예산 전달(초과 시 영문 폴백)
        tr_items = [{"id": p["cve_id"], "title": p["current_state"]["title"],
                     "description": p["current_state"]["description"]} for p in prepared]
        high_risk_ids = {p["cve_id"] for p in prepared if p["should_alert"]}
        translations = generate_korean_summaries_batch(tr_items, high_risk_ids,
                                                       deadline_ts=soft_deadline_ts)

        # Phase C: 완성 — Issue/Slack/저장 (병렬).
        # 고위험(알림 대상)을 먼저 제출해 데드라인이 닥쳐도 핵심 알림부터 완료되게 한다.
        prepared.sort(key=lambda p: (0 if p["should_alert"] else 1))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(finalize_single_cve, p, translations.get(p["cve_id"]),
                                collector, db, notifier): p["cve_id"]
                for p in prepared
            }
            for future in as_completed(futures):
                if _over_deadline():
                    executor.shutdown(wait=False, cancel_futures=True)
                    logger.warning("⏰ 시간 예산 도달 — Phase C 잔여 취소 (다음 실행에서 재처리)")
                    break
                cid = futures[future]
                try:
                    result = future.result() or {}
                    status_by_id[cid] = result.get("status", "failed")
                except Exception as e:
                    logger.error(f"{cid} 처리 중 예외 발생: {e}")
                    status_by_id[cid] = "failed"

    # 안전망: 상태가 기록되지 않은 처리 대상(취소·미완료)은 전부 failed —
    # 워터마크 계산이 이들을 '처리됨'으로 오인해 건너뛰면 영구 누락이므로 반드시 필요.
    for c in to_process:
        status_by_id.setdefault(c['cve_id'], "failed")

    # Step 8: 워터마크 전진 계산 (누락 0의 핵심)
    # 미처리(unhandled) = 실패한 처리분 + 상한으로 이월된 분. 이들의 최소 커밋시각 앞까지만 전진.
    unhandled_ts = [c['commit_ts'] for c in to_process if status_by_id.get(c['cve_id']) == 'failed']
    unhandled_ts += [c['commit_ts'] for c in deferred]
    if unhandled_ts:
        new_watermark = min(unhandled_ts)  # 이 시각 이후는 다음 실행에서 재수집
    else:
        # 전부 처리됨 → 이번에 본 가장 최신 커밋 시각까지 전진
        new_watermark = max(c['commit_ts'] for c in fetched)
    write_watermark(new_watermark)

    success_count = sum(1 for s in status_by_id.values() if s == 'success')

    # 분석 티어 소진 경고
    if rate_limit_manager.active_groq_model(config.GROQ_MODELS) is None:
        if rate_limit_manager.is_rpd_exhausted("gemini_analysis"):
            logger.warning("🚫 분석 전 티어(Groq 2모델 + Gemini 비상) 소진 → 일부 고위험 CVE 보류, 다음 실행에서 자동 재처리")
        else:
            logger.warning("⚠️ Groq 전 모델 TPD 소진 → 분석이 Gemini 비상 티어(flash-lite)로 수행됨")

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