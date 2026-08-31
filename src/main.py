"""bulk-lane — 매시간 돌며 fast-lane이 남긴 것을 채우고 무거운 대조를 수행한다.

fast-lane은 알림만 책임진다. 여기서 하는 일은 넷이다.
  ① 무거운 신호 소스 대조 (nuclei · Metasploit · ExploitDB · EPSS 전량)
  ② 알림은 나갔지만 리포트가 없는 CVE에 AI 심층 분석 리포트를 붙인다
  ③ 대시보드에 실릴 CVE의 한국어 번역
  ④ 공개 탐지 룰 재발견

무거운 일을 알림에서 떼어 낸 것이 이번 개편의 핵심이다. 예전에는 번역이 시간 예산을
다 먹으면 Critical 알림까지 통째로 다음 실행으로 밀렸다(코드 주석에 남은 실측:
"알림 5/31건만 발송"). 이제 그런 일이 구조적으로 일어나지 않는다 — 알림은 이미 나갔다.
"""
import datetime
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

import pytz
from google import genai
from google.genai import types

import ai_provenance
import enrichment_sources
import feed
import pipeline
import risk
import signal_snapshot
import state as pstate
from collector import Collector
from config import config
from database import ArgusDB
from logger import logger
from notifier import SlackNotifier
from rate_limiter import (gemini_backoff, gemini_error_kind, rate_limit_manager)
from report import create_github_issue, update_github_issue_with_official_rules
from rule_manager import RuleManager

KST = pytz.timezone('Asia/Seoul')

# Gemini 클라이언트 (한국어 번역용). HTTP 타임아웃 120초 — 응답이 행에 걸려
# 시간 예산을 통째로 잡아먹는 것을 방지. 실패는 영문 폴백이 흡수한다.
try:
    gemini_client = genai.Client(
        api_key=os.environ.get("GEMINI_API_KEY"),
        http_options=types.HttpOptions(timeout=120_000),
    )
except Exception:  # 구버전 SDK 등 http_options 미지원 시
    gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))


def _looks_english(text: str) -> bool:
    """한글이 한 글자도 없는 (=번역 안 된) 텍스트인지. 짧은 제품명 등 오탐 방지로 길이 하한."""
    t = (text or '').strip()
    return len(t) > 25 and not re.search(r'[가-힣]', t)



def translate_tracked(db: ArgusDB, deadline_ts: float) -> int:
    """대시보드에 실리는 CVE의 제목·설명을 한국어로. 갱신 건수 반환.

    fast-lane은 번역을 하지 않으므로(알림을 붙잡지 않기 위해) 추적이 시작된 CVE는 전부
    영문 상태로 들어온다. 그것을 여기서 채운다 — 이제 '백필'이 아니라 번역의 주 경로다.

    저위험 전량 추적을 그만두면서 대상이 하루 수천 건에서 수십~수백 건으로 줄어, 요청대로
    **대시보드에 실리는 것을 전부 한글화**하는 게 예산 안에 들어온다.

    조회는 updated_at 최신순이라 방금 추적을 시작한 행이 창의 앞에 온다. 그래도 못 본
    과거 행을 위해 회전 스캔(offset)을 남겨 둔다 — 창을 늘 앞에서만 잡으면 영문으로
    굳은 오래된 행을 영영 못 보기 때문이다."""
    limit = config.PERFORMANCE.get("translation_backfill_per_run", 0)
    if limit <= 0:
        return 0
    if time.time() > deadline_ts:
        logger.info("번역 생략 (시간 예산 도달)")
        return 0
    try:
        pool = config.PERFORMANCE.get("translation_backfill_pool", 200)
        # 회전 스캔 — 창을 늘 최신순 앞에서 잡으면 영문으로 굳은 과거 행을 영영 못 본다
        # (실측: 영문 잔존 111건 중 최신 200위 안에 든 건 0건이었다). 위치를 실행 간에
        # 이어붙여 전체를 한 바퀴 돈다. 12,000행 / 200 = 60회 ≈ 2.5일에 한 바퀴.
        total = db.count_tracked()
        offset = pstate.read_backfill_offset()
        if total and offset >= total:
            offset = 0
        candidates = db.get_translation_backfill_candidates(limit=pool, offset=offset)
        next_offset = 0 if (total and offset + pool >= total) or not candidates else offset + pool
        pstate.write_backfill_offset(next_offset)

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
            logger.info(f"번역: 대상 없음 (스캔 {offset:,}~{offset + len(candidates):,}"
                        f"/{total:,}행 — 다음 실행은 {next_offset:,}부터)")
            return 0

        logger.info(f"🈯 번역: 영문 {len(items)}건 처리 "
                    f"(스캔 {offset:,}~{offset + len(candidates):,}/{total:,}행)")
        translations = generate_korean_summaries_batch(items, set(), deadline_ts=deadline_ts)
        fixed = 0
        for it in items:
            tr = translations.get(it['id'])
            # 번역이 여전히 영문이면(폴백) 저장하지 않는다 — 무의미한 DB 쓰기 방지
            if not tr or _looks_english(tr[0]):
                continue
            if db.update_translation(it['id'], tr[0], tr[1]):
                fixed += 1
        # 번역 갱신은 '확인일' 보존을 위해 updated_at을 건드리지 않는다 → 증분 export가
        # 이 변경을 못 본다. 실제로 고친 게 있을 때만 전량 export를 1회 요청한다.
        # 영문 백로그가 마르면 이 경로 자체가 안 돌아 자연히 멈춘다(증분으로 복귀).
        if fixed:
            db.request_full_export()
        logger.info(f"🈯 번역 완료: {fixed}/{len(items)}건 한글화"
                    f"{' → 다음 export는 전량' if fixed else ''}")
        return fixed
    except Exception as e:
        logger.warning(f"번역 생략(오류): {e}")
        return 0



# 우리는 tools를 주지 않으므로 함수 호출 자동 처리(AFC)가 필요 없다. 끄지 않으면
# SDK가 AFC 루프로 들어가 "Models.generate_content에서 AFC 직접 사용은 권장하지
# 않는다"는 경고를 남긴다 — 동작은 같지만(도구가 없어 1회 호출 후 탈출) 로그만 흐려진다.
_NO_AFC = types.AutomaticFunctionCallingConfig(disable=True)

# 번역 2단. 한도는 모델마다 따로 잡히므로 31B가 소진돼도 26B는 그대로 남아 있다 —
# 앞 모델이 한도/서버 문제로 못 하면 뒤 모델이 이어받고, 둘 다 안 되면 영문 원문이다.
_TRANSLATION_STAGES = (
    (config.MODEL_PHASE_0, "gemini"),
    (config.MODEL_PHASE_0_FALLBACK, "gemini_fb"),
)

# 다음 모델로 넘길 사유. 한도·서버 문제는 모델이 바뀌면 풀릴 수 있지만, 안전 차단이나
# 잘못된 요청("other")은 같은 프롬프트로 같은 결과가 나온다 — 넘겨봐야 호출만 태운다.
_TR_STAGE_ADVANCE = ("skip", "rate", "transient")


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
    max_attempts = 3 if retry_on_transient else 1

    reason = "skip"
    for model, limiter_key in _TRANSLATION_STAGES:
        out, reason = _translate_one(prompt, fallback, model, limiter_key, max_attempts)
        if out is not None:
            _tr_bump("ok")
            return out
        if reason not in _TR_STAGE_ADVANCE:
            break
    _tr_bump(_TR_REASON_KEY.get(reason, "en_other"))
    return fallback


def _translate_one(prompt: str, fallback: Tuple[str, str], model: str, limiter_key: str,
                   max_attempts: int) -> Tuple[Optional[Tuple[str, str]], str]:
    """단일 CVE를 모델 하나로 번역 시도. (결과, 사유)를 반환한다.

    사유: "ok" · "skip"(일일 한도 소진) · "rate"/"transient"(다음 모델 가치 있음) ·
          "other"(안전 차단·잘못된 요청 등 — 모델을 바꿔도 같다)."""
    # 무료 Gemma는 과부하 시 503(high demand)/500(INTERNAL) 같은 일시 서버 오류를 낸다.
    # 이는 우리 한도(429)가 아니라 구글 서버측 문제. 고위험만 백오프 재시도로 회복하고
    # 저위험은 즉시 폴백. 그 외(안전 차단·잘못된 요청 등)는 재시도해도 무의미.
    for attempt in range(1, max_attempts + 1):
        try:
            if not rate_limit_manager.check_and_wait(limiter_key):
                # 일일 한도 소진 — 호출해봐야 429만 받는다
                return None, "skip"
            response = gemini_client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    # 번역은 짧음(제목 + 3줄). 출력 상한을 두지 않으면 gemma-4가
                    # 폭주 생성 → 서버 타임아웃(500 INTERNAL)을 유발한다.
                    max_output_tokens=1024,
                    temperature=0.3,
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )],
                    automatic_function_calling=_NO_AFC,
                )
            )
            # Gemini 토큰 사용량 기록 (프리티어 잔여량 가시화)
            gemini_tokens = 0
            usage = getattr(response, "usage_metadata", None)
            if usage is not None:
                gemini_tokens = getattr(usage, "total_token_count", 0) or 0
            rate_limit_manager.record_call(limiter_key, tokens_used=gemini_tokens)

            text = (response.text or "").strip()
            title_ko, desc_ko = fallback

            for line in text.split('\n'):
                if line.startswith("제목:"):
                    title_ko = line.replace("제목:", "").strip()
                if line.startswith("내용:"):
                    desc_ko = line.replace("내용:", "").strip()

            return (title_ko, desc_ko), "ok"

        except Exception as e:
            msg = str(e)
            kind = _gemini_error_kind(msg)
            if kind == "rpd":
                # 공급자가 먼저 일일 소진을 알려줬다 = 우리 카운터가 실제보다 적게 셌다는 뜻.
                # 소진으로 마킹해 이번 실행의 남은 번역이 429를 반복하지 않게 한다.
                rate_limit_manager.mark_rpd_exhausted(limiter_key)
                logger.warning(f"번역 일일 한도(RPD) 소진: {model}")
                return None, "skip"
            if kind in ("rate", "transient") and attempt < max_attempts:
                wait = _gemini_backoff(kind, attempt, msg)
                logger.warning(f"번역 {kind} 오류({model} {attempt}/{max_attempts}): {e} → {wait:.0f}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"번역 실패({model} {kind}): {e}")
            return None, kind

    return None, "transient"


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
    rpd = " · ".join(
        f"{model} {u:,}/{l:,}"
        for model, u, l in ((m,) + rate_limit_manager.rpd_status(k) for m, k in _TRANSLATION_STAGES)
    )
    logger.info(f"🈯 번역 요약(누적): 한글 {ok}건 · 영문폴백 {fallback}건 "
                f"({breakdown}) · RPD {rpd}")


def generate_korean_summaries_batch(items: List[Dict], priority_ids: set,
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
    items = sorted(items, key=lambda it: 0 if it['id'] in priority_ids else 1)

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
    응답 JSON에서 누락된 항목은 영문 폴백으로 채워 성공 시 반환값은 청크 전체를 커버한다.

    번역 2단(31B → 26B)은 개별 번역과 같은 규칙이다 — 한도/서버 문제면 뒤 모델이
    이어받고, 형식 파손·안전 차단이면 모델을 바꿔도 같으므로 넘기지 않는다."""
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
    reason = "skip"
    for model, limiter_key in _TRANSLATION_STAGES:
        out, reason = _translate_chunk_with(chunk, prompt, model, limiter_key, max_attempts)
        if out is not None:
            return out, "ok"
        if reason not in _TR_STAGE_ADVANCE:
            return None, reason
    return None, reason


def _translate_chunk_with(chunk: List[Dict], prompt: str, model: str, limiter_key: str,
                          max_attempts: int) -> Tuple[Optional[Dict[str, Tuple[str, str]]], str]:
    """청크를 모델 하나로 번역 시도. 사유는 _translate_chunk와 같은 어휘를 쓴다."""
    for attempt in range(1, max_attempts + 1):
        try:
            if not rate_limit_manager.check_and_wait(limiter_key):
                return None, "skip"
            response = gemini_client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    max_output_tokens=3072,  # 6건 × 제목+2줄 요약 — 잘림 방지(JSON 완결)
                    temperature=0.3,
                    safety_settings=[types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE"
                    )],
                    automatic_function_calling=_NO_AFC,
                )
            )
            tokens = 0
            usage = getattr(response, "usage_metadata", None)
            if usage is not None:
                tokens = getattr(usage, "total_token_count", 0) or 0
            rate_limit_manager.record_call(limiter_key, tokens_used=tokens)

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
                rate_limit_manager.mark_rpd_exhausted(limiter_key)
                logger.warning(f"일괄 번역 일일 한도(RPD) 소진: {model}")
                return None, "skip"
            if kind in ("rate", "transient") and attempt < max_attempts:
                wait = _gemini_backoff(kind, attempt, msg)
                logger.warning(f"일괄 번역 {kind} 오류({model} {attempt}/{max_attempts}): {e} → {wait:.0f}s 후 재시도")
                time.sleep(wait)
                continue
            logger.warning(f"일괄 번역 청크 실패({model} {kind}): {e}")
            return None, kind
    return None, "api"


def check_for_official_rules(db: ArgusDB, notifier: SlackNotifier) -> None:
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
                except Exception as e:
                    # 실패해도 다음 실행에서 재시도되므로 치명적이지 않지만, 계속
                    # 실패하면 같은 CVE를 매번 다시 검색하게 되므로 흔적을 남긴다.
                    logger.warning(f"{cve_id} 룰 재확인 쿨다운 기록 실패: {e}")
                continue

        logger.info(f"=== 공식 룰 재발견 체크 완료 (발견: {found_count}건) ===")

    except Exception as e:
        logger.error(f"공식 룰 체크 프로세스 실패: {e}")



# ==============================================================================
# 리포트 보강 — 알림은 나갔는데 상세 리포트가 없는 건을 채운다
# ==============================================================================
def backfill_reports(db: ArgusDB, deadline_ts: float, limit: int = 20) -> int:
    """T0/T1 알림이 나간 CVE 중 report_url이 없는 것에 AI 심층 분석 리포트를 붙인다.

    fast-lane은 Issue를 만들지 않는다 — AI 분석은 느리고, 알림이 그 지연을 기다릴
    이유가 없기 때문이다. Slack은 이미 갔고, 여기서 '읽을 문서'를 뒤이어 만든다.

    분석 2단이 모두 소진이면 건너뛴다. report_url이 여전히 비어 있어 다음 실행이
    같은 건을 다시 집으므로 유실이 아니라 지연이다."""
    if (rate_limit_manager.is_rpd_exhausted("gemini_analysis")
            and rate_limit_manager.is_rpd_exhausted("gemini_analysis_fb")):
        logger.warning("분석 2단 모두 소진 → 리포트 보강 생략 (다음 실행 재시도)")
        return 0

    rows = db.get_missing_report_candidates(limit=limit)
    if not rows:
        logger.info("리포트 보강: 대상 없음")
        return 0

    logger.info(f"📝 리포트 보강 대상 {len(rows)}건")
    made = 0
    for row in rows:
        if time.time() > deadline_ts:
            logger.warning("⏰ 시간 예산 도달 — 리포트 보강 중단 (다음 실행 이어받음)")
            break
        state = row.get('last_alert_state') or {}
        state.setdefault('id', row['id'])
        state.setdefault('cvss', row.get('cvss_score') or 0.0)
        state.setdefault('epss', row.get('epss_score') or 0.0)
        state.setdefault('is_kev', bool(row.get('is_kev')))
        state.setdefault('references', [])
        # 리포트 제목은 한국어를 쓴다. 아직 번역 전이면 영문 제목으로 낸다 —
        # 리포트를 번역까지 기다리게 하면 그만큼 대응이 늦어진다.
        state.setdefault('title_ko', state.get('title') or row['id'])
        reason = " · ".join(
            risk.TRIGGERS[k].label for k in (state.get('fired_triggers') or [])
            if k in risk.TRIGGERS) or "고위험 판정"
        try:
            url, rules_info = create_github_issue(state, reason)
        except Exception as e:
            logger.error(f"{row['id']} 리포트 생성 실패: {e}")
            continue
        if not url:
            continue
        payload = {"id": row['id'], "report_url": url,
                   "updated_at": row.get('updated_at')
                   or datetime.datetime.now(KST).isoformat()}
        if rules_info:
            payload["has_official_rules"] = rules_info.get('has_official', False)
            payload["rules_snapshot"] = rules_info.get('rules')
            payload["last_rule_check_at"] = datetime.datetime.now(KST).isoformat()
        if db.upsert_cve(payload):
            made += 1
    logger.info(f"📝 리포트 보강 완료: {made}/{len(rows)}건")
    return made


# ==============================================================================
# 무거운 신호 대조
# ==============================================================================
def sweep_heavy_signals(collector: Collector, db: ArgusDB, notifier: SlackNotifier,
                        deadline_ts: float) -> List[pipeline.Outcome]:
    """nuclei · Metasploit · ExploitDB · EPSS 전량을 지난 회차와 대조한다.

    수 MB짜리 인덱스라 5분 주기에는 무겁다. 대신 이 신호들은 분 단위로 다투는 성격이
    아니다 — 템플릿이나 모듈이 공개되는 것은 시간 단위 사건이다."""
    outcomes: List[pipeline.Outcome] = []
    cap = config.PERFORMANCE.get("snapshot_cap", 80)
    epss_index = enrichment_sources.load_epss_above(risk.EPSS_P_HIGH)

    for diff in signal_snapshot.sweep(db, cap=cap,
                                      only=[k for k, s in signal_snapshot.SOURCES.items()
                                            if not s.fast]):
        if not diff.added:
            continue
        processed: List[str] = []
        for cve_id in diff.added:
            if time.time() > deadline_ts:
                logger.warning(f"⏰ [{diff.source.label}] 시간 예산 도달 — 나머지는 다음 실행")
                break
            record = feed.fetch_record(cve_id)
            if record is None:
                continue
            try:
                st = pipeline.build_state(cve_id, record, collector, epss_index)
            except Exception as e:
                logger.warning(f"{cve_id} 상태 구성 실패: {e}")
                continue
            if st is None:
                processed.append(cve_id)
                continue
            out = pipeline.process(st, db, notifier,
                                   reason_prefix=f"[{diff.source.label}] ",
                                   make_report=create_github_issue)
            outcomes.append(out)
            if not out.needs_retry:
                processed.append(cve_id)
        signal_snapshot.commit(db, diff, processed)
    return outcomes


# ==============================================================================
# 메인
# ==============================================================================
def _dashboard_url() -> Optional[str]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return None
    owner, name = repo.split("/", 1)
    return f"https://{owner.lower()}.github.io/{name}/"


def _main() -> None:
    started = time.time()
    logger.info("=" * 60)
    logger.info("Argus bulk-lane 시작")
    logger.info("=" * 60)

    if not all(config.health_check().values()):
        logger.error("헬스체크 실패")
        return

    deadline = started + config.PERFORMANCE.get("bulk_deadline_minutes", 38) * 60
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    rate_limit_manager.import_rpd_state(pstate.read_rpd_state())

    collector.fetch_kev()
    collector.fetch_vulncheck_kev()
    # Anthropic 공개 레저 — 2.3MB라 5분 주기(fast-lane)에는 무겁다. 여기서 적재해
    # collector에 넘기면 이 회차의 판정이 ANT ID까지 본다. fast-lane은 레코드 크레딧
    # 경로만 쓰는데, 그쪽은 이미 받은 레코드 안에 있어 비용이 0이다.
    collector.ai_ledger = ai_provenance.load_anthropic_ledger()

    # ① 무거운 신호 대조 — 새 무기화 신호는 알림이 나가야 하므로 가장 먼저
    outcomes = sweep_heavy_signals(collector, db, notifier, deadline)
    if outcomes:
        logger.info(pipeline.summarize(outcomes))

    # ② 리포트 보강 — fast-lane이 Slack만 보낸 건에 읽을 문서를 붙인다
    backfill_reports(db, deadline)

    # ③ 번역 — 대시보드에 실리는 것을 전부 한글로
    translate_tracked(db, deadline)

    # ④ 공개 탐지 룰 재발견 (있으면 기존 Issue에 댓글)
    if time.time() < deadline:
        check_for_official_rules(db, notifier)

    pstate.write_rpd_state(rate_limit_manager.export_rpd_state())

    tracked = sum(1 for o in outcomes if o.status == "tracked")
    notifier.send_batch_summary(dashboard_url=_dashboard_url(), tracked=tracked)

    logger.info("=" * 60)
    logger.info(f"bulk-lane 완료 · {time.time() - started:.1f}초")
    logger.info("=" * 60)
    rate_limit_manager.print_summary()


def _notify_pipeline_failure(error: Exception) -> None:
    """최상위 실패를 Slack에 알림 (알림 자체의 실패는 무시하고 넘어간다)."""
    try:
        SlackNotifier().send_pipeline_warning(
            "🔴 Argus bulk-lane 실패", f"```{type(error).__name__}: {error}```")
    except Exception:
        pass


def main() -> None:
    try:
        _main()
    except Exception as e:
        logger.error(f"bulk-lane 최상위 실패: {e}", exc_info=True)
        _notify_pipeline_failure(e)


if __name__ == "__main__":
    main()
