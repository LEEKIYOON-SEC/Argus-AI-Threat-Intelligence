import time
import threading
import re
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from logger import logger

def is_transient_gemini_error(msg: str) -> bool:
    """Gemini/Gemma 일시 서버 오류(재시도 가치 있음) 판별.
    상태 코드는 단어 경계로 매칭 — "limit: 1500" 같은 숫자에 "500"이 오탐되지 않게."""
    return bool(re.search(r'\b(500|503)\b', msg)) or any(t in msg for t in (
        "INTERNAL", "UNAVAILABLE", "high demand", "overloaded", "try again"
    ))


def gemini_error_kind(msg: str) -> str:
    """Google AI Studio 호출 예외를 '어떻게 대응해야 하는가'로 분류한다.

    rpd       — 일일 요청 한도 소진(429). 기다려도 오늘 안에는 풀리지 않는다 →
                즉시 소진 마킹하고 남은 호출은 폴백.
    rate      — 분당 요청 한도(429). 짧게 기다리면 풀린다 → 백오프 후 재시도.
    transient — 구글 서버측 일시 오류(500/503). 백오프 후 재시도.
    other     — 안전 차단·잘못된 요청 등. 재시도해도 결과가 같다.

    분당/일일 모두 429로 오기 때문에 메시지의 per-day 표기가 있을 때만 rpd로 본다.
    분당 한도를 일일 소진으로 오판하면 — 소진 상태가 상태 파일로 실행 간에 유지되므로 —
    아직 남은 하루치 한도를 통째로 버리게 된다.
    """
    low = msg.lower()
    if "429" in msg or "resource_exhausted" in low or "resource exhausted" in low:
        if any(t in low for t in ("perday", "per day", "per-day", "daily")):
            return "rpd"
        return "rate"
    if is_transient_gemini_error(msg):
        return "transient"
    return "other"


def gemini_backoff(kind: str, attempt: int, msg: str, manager=None) -> float:
    """재시도 전 대기 시간. 분당 한도(429)는 서버가 알려준 재개 시각을 우선 따르되,
    파이프라인이 통째로 잠들지 않도록 상한(30초)을 둔다.

    분류(gemini_error_kind)와 같은 파일에 둔다 — 번역과 분석이 서로 다른 규칙으로
    기다리면 한쪽만 조용히 예산을 더 태우게 된다."""
    if kind == "rate":
        hinted = (manager or rate_limit_manager).parse_retry_after(msg)
        return min(hinted if hinted else 8.0 * attempt, 30.0)
    return 2.0 * attempt  # 503/500: 2s, 4s


@dataclass
class RateLimitInfo:
    """API Rate Limit 정보"""
    limit: int
    used: int = 0
    reset_at: datetime = field(default_factory=datetime.now)
    window_seconds: int = 3600
    min_interval: float = 0.0
    last_call_at: float = 0.0
    
    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)
    
    @property
    def usage_percent(self) -> float:
        if self.limit == 0:
            return 0
        return (self.used / self.limit) * 100
    
    @property
    def is_exhausted(self) -> bool:
        return self.used >= self.limit
    
    @property
    def time_until_reset(self) -> float:
        now = datetime.now()
        if now >= self.reset_at:
            return 0
        return (self.reset_at - now).total_seconds()
    
class RateLimitManager:
    def __init__(self):
        self.limits: Dict[str, RateLimitInfo] = {
            "github": RateLimitInfo(
                limit=5000,
                window_seconds=3600,
                min_interval=0.5
            ),
            "epss": RateLimitInfo(
                limit=60,
                window_seconds=60,
                min_interval=1.0
            ),
            "kev": RateLimitInfo(
                limit=10,
                window_seconds=3600,
                min_interval=2.0
            ),
            # 아래 4개는 Google AI Studio 모델별 한도(콘솔 실측). 모델마다 따로 잡히므로
            # 한 모델이 소진돼도 다른 모델은 멀쩡하다 — 그래서 키를 나눈다.
            #
            # 번역 Gemma 4 31B: RPM 30 / TPM 16K / RPD 14.4K. 실측 병목은 RPD(4%)가
            # 아니라 TPM(76%)·RPM(87%)이라 min_interval로 분당 유입을 눌러 둔다.
            "gemini": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
            ),
            # 번역 폴백 Gemma 4 26B: RPM 30 / TPM 16K. 31B와 같은 등급으로 본다.
            "gemini_fb": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
            ),
            # 분석 Gemini 3.5 Flash-Lite: RPM 15 / TPM 250K / RPD 500.
            "gemini_analysis": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            # 분석 폴백 Gemini 3.1 Flash-Lite: 3.5와 동일 한도.
            "gemini_analysis_fb": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            # NVD API: API키 있으면 50req/30초
            "nvd": RateLimitInfo(
                limit=40,
                window_seconds=30,
                min_interval=1.0
            ),
            # VulnCheck Free: 50req/분
            "vulncheck": RateLimitInfo(
                limit=40,
                window_seconds=60,
                min_interval=1.5
            ),
            # GitHub Advisory API: REST 코어 한도(토큰당 5,000/h)를 github 버킷과 공유.
            # 실측 사용량(수집+enrich+PoC ≈ 1,200/h)을 감안해 900/h까지 허용 — 100/h는
            # 지나치게 보수적이라 고위험 100건+ 실행에서 매번 소진 로그를 냈다.
            "github_advisory": RateLimitInfo(
                limit=900,
                window_seconds=3600,
                min_interval=0.5
            ),
            "ruleset_download": RateLimitInfo(
                limit=20,
                window_seconds=3600,
                min_interval=2.0
            )
        }
        
        self._lock = threading.Lock()
        # 소진-SKIP 경고 중복 억제 (같은 윈도우 내 반복 경고는 debug로 강등)
        self._skip_warned_at: Dict[str, datetime] = {}

        self.stats = {
            "total_calls": 0,
            "total_waits": 0,
            "total_wait_time": 0.0,
            "rate_limit_hits": 0
        }

        # TPM(Tokens Per Minute) 선제 관리 — 번역만 등록한다. 콘솔 실측에서 병목이
        # RPD(4%)나 RPM이 아니라 TPM(76%)이었기 때문이다. 넘기면 429를 맞고 30초씩
        # 백오프하느니, 분 리셋까지 잠깐 기다리는 편이 싸다.
        # 분석(flash-lite)은 TPM 250K에 호출이 하루 수십 건이라 등록할 이유가 없다.
        self._tpm_limits: Dict[str, int] = {
            "gemini": 16_000,     # Gemma 4 31B
            "gemini_fb": 16_000,  # Gemma 4 26B
        }
        self._tpm_reserve: Dict[str, int] = {
            # 배치 1콜 추정: 6건 × (제목+500자 설명) 입력 + 최대 3,072 출력
            "gemini": 4_000,
            "gemini_fb": 4_000,
        }
        self._tpm_used: Dict[str, int] = {api: 0 for api in self._tpm_limits}
        self._tpm_reset_at: Dict[str, datetime] = {
            api: datetime.now() + timedelta(seconds=60) for api in self._tpm_limits
        }

        # RPD (Requests Per Day) 트래킹. 호출당 1건 누적, 90% 도달 시 경고.
        # AI Studio 콘솔 실측치. 예전에는 추정치를 넣어 두 값 모두 틀렸다 —
        # 번역은 실제 14,400인데 1,500에서 끊고 있었고, 분석은 실제 500인데 1,000까지
        # 허용해 한도 전에 막지 못했다.
        self._rpd_limits: Dict[str, int] = {
            "gemini": 14_400,             # Gemma 4 31B (번역)
            "gemini_fb": 14_400,          # Gemma 4 26B (번역 폴백)
            "gemini_analysis": 500,       # Gemini 3.5 Flash-Lite (분석)
            "gemini_analysis_fb": 500,    # Gemini 3.1 Flash-Lite (분석 폴백)
        }
        self._rpd_used: Dict[str, int] = {api: 0 for api in self._rpd_limits}
        # RPD는 시간 단위 버킷의 롤링 24시간 합으로 센다. 이유는 두 가지다.
        #  ① 프로세스는 매 실행 새로 뜨므로 메모리 카운터만으로는 항상 0에서 시작한다
        #     → 한도를 모른 채 계속 호출해 결국 공급자가 429로 끊는다. 버킷을 상태 파일에
        #     저장해 실행 간에 이어붙인다(import_rpd_state / export_rpd_state).
        #  ② 공급자의 일간 리셋 시각(태평양 자정 등)을 우리가 정확히 알 수 없다. 롤링
        #     24시간 합은 '마지막 리셋 이후 사용량'보다 항상 크거나 같아서 안전한 쪽으로
        #     틀린다 — 달력일 기준으로 세면 UTC 새벽 구간에서 과소 집계돼 초과할 수 있다.
        self._rpd_buckets: Dict[str, Dict[str, int]] = {api: {} for api in self._rpd_limits}
        self._rpd_skip_warned: Dict[str, bool] = {}   # SKIP 경고 1회만 (로그 스팸 방지)

        logger.info("Rate Limit Manager 초기화 완료 (Thread-Safe · RPM/TPM/RPD 모델별 추적)")

    def check_and_wait(self, api_name: str, max_wait: Optional[float] = None) -> bool:
        """API 호출 전 반드시 호출. Lock으로 동시 접근 차단.

        max_wait: 한도 소진 시 리셋까지 이보다 오래 기다려야 하면 대기 대신 False를
        반환한다(호출부가 해당 보강을 SKIP). 부가 정보 API(advisory/PoC)가 수십 분
        잠들며 파이프라인 전체(타임아웃 30분)를 막는 것을 방지."""
        if api_name not in self.limits:
            logger.warning(f"알 수 없는 API: {api_name}, Rate Limit 적용 안 됨")
            return True

        exhausted_wait = 0.0
        with self._lock:
            # 일간 한도(RPD) 소진은 분 단위 대기로 풀리지 않는다 → 즉시 False로 알려
            # 호출부가 폴백하게 한다. 이 검사가 없으면 소진 마킹을 해도 계속 호출한다.
            rpd_limit = self._rpd_limits.get(api_name)
            if rpd_limit is not None and self._rpd_rolling_sum(api_name) >= rpd_limit:
                if not self._rpd_skip_warned.get(api_name):
                    logger.warning(f"⏭️ {api_name} 일일 한도(RPD {rpd_limit:,}) 소진 — "
                                   f"이번 실행의 후속 호출은 SKIP")
                    self._rpd_skip_warned[api_name] = True
                return False

            info = self.limits[api_name]
            now = datetime.now()

            if now >= info.reset_at:
                old_used = info.used
                info.used = 0
                info.reset_at = now + timedelta(seconds=info.window_seconds)
                if old_used > 0:
                    logger.debug(f"{api_name} Rate Limit 리셋 (이전 사용: {old_used}/{info.limit})")

            if info.min_interval > 0 and info.last_call_at > 0:
                elapsed = time.time() - info.last_call_at
                if elapsed < info.min_interval:
                    wait_time = info.min_interval - elapsed
                    logger.debug(f"{api_name} 최소 간격 대기: {wait_time:.1f}초")
                    time.sleep(wait_time)
                    self.stats["total_wait_time"] += wait_time

            if info.is_exhausted:
                wait_time = info.time_until_reset
                if wait_time <= 0:
                    wait_time = info.window_seconds
                if max_wait is not None and wait_time > max_wait:
                    # 같은 윈도우 내 반복 SKIP은 debug로 — 경고 스팸 방지 (첫 회만 warning)
                    last_warn = self._skip_warned_at.get(api_name)
                    if last_warn is None or last_warn < info.reset_at - timedelta(seconds=info.window_seconds):
                        logger.warning(
                            f"⏭️ {api_name} 한도 소진 ({info.used}/{info.limit}) — "
                            f"{wait_time:.0f}초 대기 대신 SKIP (이 윈도우의 후속 SKIP 로그는 생략)"
                        )
                        self._skip_warned_at[api_name] = now
                    else:
                        logger.debug(f"{api_name} 한도 소진 SKIP")
                    return False
                exhausted_wait = wait_time
                logger.warning(
                    f"⚠️ {api_name} Rate Limit 도달! "
                    f"({info.used}/{info.limit}) "
                    f"{wait_time:.0f}초 대기 중..."
                )

        # 장시간 대기는 락 밖에서 — 락을 쥔 채 잠들면 모든 API 호출(전 워커)이 봉쇄된다
        if exhausted_wait > 0:
            time.sleep(exhausted_wait + 1)
            with self._lock:
                self.stats["total_waits"] += 1
                self.stats["total_wait_time"] += exhausted_wait
                info = self.limits[api_name]
                info.used = 0
                info.reset_at = datetime.now() + timedelta(seconds=info.window_seconds)
            return True

        with self._lock:
            info = self.limits[api_name]
            usage = info.usage_percent
            if usage >= 90:
                extra_wait = info.min_interval * 2 if info.min_interval > 0 else 5.0
                logger.warning(
                    f"⚠️ {api_name} 사용률 높음: {usage:.1f}% "
                    f"({info.remaining}개 남음) - {extra_wait:.1f}초 추가 대기"
                )
                time.sleep(extra_wait)
                self.stats["total_wait_time"] += extra_wait
            elif usage >= 80:
                extra_wait = info.min_interval if info.min_interval > 0 else 2.0
                logger.debug(f"{api_name} 사용률: {usage:.1f}% - 속도 조절")
                time.sleep(extra_wait)
                self.stats["total_wait_time"] += extra_wait

            # TPM 선제 관리: 이번 분 예약분이 한도에 근접하면 분 리셋까지 대기 (429 폭주 사전 차단)
            if api_name in self._tpm_limits:
                now = datetime.now()
                if now >= self._tpm_reset_at[api_name]:
                    self._tpm_used[api_name] = 0
                    self._tpm_reset_at[api_name] = now + timedelta(seconds=60)
                reserve = self._tpm_reserve.get(api_name, 0)
                tpm_limit = self._tpm_limits[api_name]
                if self._tpm_used[api_name] + reserve > tpm_limit:
                    wait_time = (self._tpm_reset_at[api_name] - now).total_seconds()
                    if wait_time > 0:
                        logger.warning(
                            f"⏳ {api_name} TPM 예약 한도 근접 "
                            f"({self._tpm_used[api_name]}/{tpm_limit}), {wait_time:.0f}초 대기(분 리셋)"
                        )
                        time.sleep(wait_time + 0.5)
                        self.stats["total_waits"] += 1
                        self.stats["total_wait_time"] += wait_time
                    self._tpm_used[api_name] = 0
                    self._tpm_reset_at[api_name] = datetime.now() + timedelta(seconds=60)

        return True
    
    def record_call(self, api_name: str, tokens_used: int = 0):
        """API 호출 기록 (Thread-Safe). tokens_used가 있으면 TPM도 업데이트."""
        if api_name not in self.limits:
            return
        with self._lock:
            info = self.limits[api_name]
            info.used += 1
            info.last_call_at = time.time()
            self.stats["total_calls"] += 1
            logger.debug(f"{api_name} 호출 기록: {info.used}/{info.limit} ({info.usage_percent:.1f}%)")

            # RPD 트래킹 (롤링 24h) — 토큰과 무관하게 호출 1건마다 누적 (Gemma는 TPM 무제한)
            if api_name in self._rpd_limits:
                buckets = self._rpd_buckets[api_name]
                key = self._rpd_bucket_key()
                buckets[key] = buckets.get(key, 0) + 1
                self._rpd_used[api_name] = self._rpd_rolling_sum(api_name)
                rpd_limit = self._rpd_limits[api_name]
                rpd_pct = (self._rpd_used[api_name] / rpd_limit) * 100
                logger.debug(f"{api_name} RPD: {self._rpd_used[api_name]:,}/{rpd_limit:,} ({rpd_pct:.1f}%)")
                if rpd_pct >= 90:
                    logger.warning(f"⚠️ {api_name} RPD 90% 도달! ({self._rpd_used[api_name]:,}/{rpd_limit:,})")

            # TPM 트래킹 (분 윈도우) — 실제 소비 토큰 누적
            if tokens_used > 0 and api_name in self._tpm_limits:
                now = datetime.now()
                if now >= self._tpm_reset_at[api_name]:
                    self._tpm_used[api_name] = 0
                    self._tpm_reset_at[api_name] = now + timedelta(seconds=60)
                self._tpm_used[api_name] += tokens_used


    @staticmethod
    def _rpd_bucket_key(when: Optional[datetime] = None) -> str:
        """RPD 버킷 키 = UTC 시간 단위. 로컬 시간대에 무관하게 재현되도록 UTC로 고정."""
        return (when or datetime.now(timezone.utc)).astimezone(
            timezone.utc).strftime("%Y-%m-%dT%H")

    def _rpd_rolling_sum(self, api_name: str) -> int:
        """최근 24시간 버킷 합. 오래된 버킷은 이 시점에 정리한다. (호출자가 락 보유)"""
        buckets = self._rpd_buckets.get(api_name)
        if not buckets:
            return 0
        cutoff = self._rpd_bucket_key(datetime.now(timezone.utc) - timedelta(hours=23))
        for key in [k for k in buckets if k < cutoff]:
            del buckets[key]
        return sum(buckets.values())

    def import_rpd_state(self, state: Dict[str, Dict[str, int]]) -> None:
        """이전 실행의 RPD 버킷을 불러온다. 형식이 어긋난 값은 조용히 버린다
        (상태 파일이 손상돼도 파이프라인이 멈추면 안 되므로)."""
        if not isinstance(state, dict):
            return
        with self._lock:
            for api, buckets in state.items():
                if api not in self._rpd_limits or not isinstance(buckets, dict):
                    continue
                clean = {str(k): int(v) for k, v in buckets.items()
                         if isinstance(v, (int, float)) and int(v) > 0}
                self._rpd_buckets[api] = clean
                self._rpd_used[api] = self._rpd_rolling_sum(api)
                if self._rpd_used[api]:
                    logger.info(f"🔁 {api} RPD 이월: 최근 24h {self._rpd_used[api]:,}"
                                f"/{self._rpd_limits[api]:,}")

    def export_rpd_state(self) -> Dict[str, Dict[str, int]]:
        """상태 파일에 저장할 RPD 버킷. 최근 24시간만 남긴다."""
        with self._lock:
            out = {}
            for api in self._rpd_limits:
                self._rpd_rolling_sum(api)      # 오래된 버킷 정리
                if self._rpd_buckets[api]:
                    out[api] = dict(self._rpd_buckets[api])
            return out

    def rpd_status(self, api_name: str) -> tuple:
        """(최근 24h 사용량, 한도). 추적 대상이 아니면 (0, 0) — 로그 표시용."""
        with self._lock:
            limit = self._rpd_limits.get(api_name)
            if limit is None:
                return (0, 0)
            return (self._rpd_rolling_sum(api_name), limit)

    def is_rpd_exhausted(self, api_name: str) -> bool:
        """일간 요청 한도(RPD) 추적 대상 API의 소진 여부. 미추적 API는 False."""
        with self._lock:
            limit = self._rpd_limits.get(api_name)
            if limit is None:
                return False
            return self._rpd_rolling_sum(api_name) >= limit

    def mark_rpd_exhausted(self, api_name: str) -> None:
        """RPD 소진 마킹 (일간 quota 429 수신 시 — 대기 무의미, 즉시 스킵 전환).

        공급자가 먼저 429를 냈다는 건 우리 카운터가 실제보다 적게 세고 있었다는 뜻이다.
        남은 한도를 0으로 만들어 이번 실행에서 더 호출하지 않게 한다."""
        with self._lock:
            if api_name in self._rpd_limits:
                limit = self._rpd_limits[api_name]
                shortfall = max(0, limit - self._rpd_rolling_sum(api_name))
                if shortfall:
                    key = self._rpd_bucket_key()
                    self._rpd_buckets[api_name][key] = (
                        self._rpd_buckets[api_name].get(key, 0) + shortfall)
                self._rpd_used[api_name] = self._rpd_rolling_sum(api_name)
                logger.warning(f"🚫 {api_name} 일일 한도(RPD) 소진 마킹 — SKIP 전환")

    @staticmethod
    def parse_retry_after(error_message: str) -> Optional[float]:
        """
        에러 메시지에서 대기 시간 추출

        지원 형식:
        - "try again in 10m3.072s" → 603.072초
        - "try again in 45.5s" → 45.5초
        - "try again in 2m" → 120초
        - "Retry-After: 60" → 60초
        - Google AI Studio의 retryDelay 필드 → 그 값
        """
        msg = str(error_message)

        # Google AI Studio는 429 본문에 {"retryDelay": "27s"} 형태로 재개 시각을 준다.
        # 아래 "retry in ..." 패턴만 보면 이걸 놓치고 기본 백오프로 떨어진다 —
        # 서버가 알려준 값을 두고 임의로 기다리면 429를 한 번 더 받는다.
        match = re.search(r'retryDelay["\']?\s*[:=]\s*["\']?(?:(\d+)m)?(\d+\.?\d*)s',
                          msg, re.IGNORECASE)
        if match:
            return int(match.group(1) or 0) * 60 + float(match.group(2))

        # 분+초 복합 형식: "10m3.072s", "2m30s"
        match = re.search(r'(?:retry|try again) in (\d+)m(\d+\.?\d*)s', msg, re.IGNORECASE)
        if match:
            minutes = int(match.group(1))
            seconds = float(match.group(2))
            return minutes * 60 + seconds

        # 분만: "2m", "10m"
        match = re.search(r'(?:retry|try again) in (\d+)m\b', msg, re.IGNORECASE)
        if match:
            return int(match.group(1)) * 60.0

        # 초만: "45.5s", "10s"
        match = re.search(r'(?:retry|try again) in (\d+\.?\d*)s', msg, re.IGNORECASE)
        if match:
            return float(match.group(1))

        # HTTP 표준 헤더: "Retry-After: 60"
        match = re.search(r'Retry-After:\s*(\d+)', msg)
        if match:
            return float(match.group(1))

        return None
    
    def print_summary(self):
        """실행 종료 시 요약 출력"""
        logger.info("")
        logger.info("=" * 60)
        logger.info("📊 Rate Limit 사용 요약")
        logger.info("=" * 60)
        for name, info in self.limits.items():
            if info.used > 0 or info.last_call_at > 0:
                usage_bar = self._create_usage_bar(info.usage_percent)
                logger.info(
                    f"  {name:18s}: {info.used:4d}/{info.limit:4d} "
                    f"[{usage_bar}] {info.usage_percent:5.1f}%"
                )
        # RPD 요약 (모델별 일간 요청 수)
        for api, limit in self._rpd_limits.items():
            used = self._rpd_used.get(api, 0)
            if used > 0:
                rpd_pct = (used / limit) * 100
                rpd_bar = self._create_usage_bar(rpd_pct)
                logger.info(
                    f"  {api + ' RPD':18s}: {used:,}/{limit:,} "
                    f"[{rpd_bar}] {rpd_pct:5.1f}%"
                )
        logger.info("-" * 60)
        logger.info(f"  총 API 호출: {self.stats['total_calls']}회")
        logger.info(f"  Rate Limit 대기: {self.stats['total_waits']}회")
        logger.info(f"  429 응답 수신: {self.stats['rate_limit_hits']}회")
        logger.info(f"  총 대기 시간: {self.stats['total_wait_time']:.1f}초")
        logger.info("=" * 60)
    
    def _create_usage_bar(self, percent: float) -> str:
        bar_length = 10
        filled = int((percent / 100) * bar_length)
        empty = bar_length - filled
        if percent >= 90: symbol = "█"
        elif percent >= 70: symbol = "▓"
        else: symbol = "░"
        return symbol * filled + "░" * empty

rate_limit_manager = RateLimitManager()