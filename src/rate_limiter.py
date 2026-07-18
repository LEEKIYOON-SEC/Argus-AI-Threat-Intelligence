import time
import threading
import re
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from logger import logger

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
            # Groq Free Tier: RPM 30 (분당 요청). 일일 한도(TPD 200K)는
            # gpt-oss/qwen 모델별로 별도 카운터로 추적.
            "groq": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
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
            # Gemma 4 Free Tier: RPM 15 / TPM 무제한 / RPD 1,500 (번역 전용)
            "gemini": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            # Gemini flash-lite (분석 비상 폴백 전용) — 번역과 별도 모델·별도 한도.
            # 보수적 기본값 RPM 10. 실제 한도는 AI Studio 콘솔 확인 후 조정.
            "gemini_analysis": RateLimitInfo(
                limit=10,
                window_seconds=60,
                min_interval=6.0
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
            # GitHub Advisory API: 일반 GitHub API 한도 공유
            "github_advisory": RateLimitInfo(
                limit=100,
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

        self.stats = {
            "total_calls": 0,
            "total_waits": 0,
            "total_wait_time": 0.0,
            "rate_limit_hits": 0
        }

        # Groq 모델별 일일 한도 트래킹 — gpt-oss·qwen 각각 TPD 200K가 별도로 잡힌다.
        # 요청 수(_gr_req)와 토큰 수(_tpd_used)를 모델별로 누적하고, 한도를 넘으면 소진으로
        # 보고 다음 모델(캐스케이드)로 넘어간다. (rpd 기준도 지원하나 현 캐스케이드는 tpd만 사용.)
        # (실행마다 상태 초기화 + 429 감지로 실제 일간 소진 반영.)
        self._tpd_used_model: Dict[str, int] = {}   # 모델별 누적 토큰
        self._gr_req_model: Dict[str, int] = {}     # 모델별 누적 요청 수
        self._tpd_reset_model: Dict[str, datetime] = {}
        self._tpd_exhausted_model: Dict[str, bool] = {}

        # TPM (Tokens Per Minute) 선제 관리 — gpt-oss/qwen 모두 TPM 250K.
        # 호출당 예약(~6K) « 250K라 사실상 발동 안 하는 안전장치.
        self._tpm_limits: Dict[str, int] = {
            "groq": 250_000,  # gpt-oss-120b / qwen3.6 공통 TPM
        }
        self._tpm_reserve: Dict[str, int] = {
            "groq": 6_000,  # 호출당 예약 추정(입력 + max_completion 4096)
        }
        self._tpm_used: Dict[str, int] = {api: 0 for api in self._tpm_limits}
        self._tpm_reset_at: Dict[str, datetime] = {
            api: datetime.now() + timedelta(seconds=60) for api in self._tpm_limits
        }

        # RPD (Requests Per Day) 트래킹 — Gemma 4 무료는 TPM이 무제한이라 일간 요청 수(1,500)가
        # 실질적 일간 상한이다(토큰이 아님). 호출당 1건 누적, 90% 도달 시 경고.
        self._rpd_limits: Dict[str, int] = {
            "gemini": 1_500,           # Gemma 4 (번역): RPD 1,500
            "gemini_analysis": 1_000,  # flash-lite (분석 비상): 보수적 기본값 — 콘솔 확인 후 조정
        }
        self._rpd_used: Dict[str, int] = {api: 0 for api in self._rpd_limits}
        self._rpd_reset_at: Dict[str, datetime] = {
            api: datetime.now() + timedelta(hours=24) for api in self._rpd_limits
        }

        logger.info("Rate Limit Manager v3.5 초기화 완료 (Thread-Safe + 모델별 RPD/TPD 캐스케이드)")

    @staticmethod
    def _groq_model_limits(model: str) -> Dict[str, Optional[int]]:
        """모델의 일일 한도 {rpd, tpd} 조회 (config). 미등록 시 TPD 200K 기본."""
        try:
            from config import config
            return config.GROQ_MODEL_LIMITS.get(model, {"rpd": None, "tpd": 200_000})
        except Exception:
            return {"rpd": None, "tpd": 200_000}

    def _ensure_groq_model(self, model: str) -> None:
        """모델별 카운터 지연 초기화. 반드시 _lock 보유 상태에서 호출."""
        if model not in self._tpd_used_model:
            self._tpd_used_model[model] = 0
            self._gr_req_model[model] = 0
            self._tpd_reset_model[model] = datetime.now() + timedelta(hours=24)
            self._tpd_exhausted_model[model] = False

    def _groq_model_exhausted(self, model: str, required_tokens: int) -> bool:
        """이 모델이 다음 호출을 감당 못 하는지 (rpd 또는 tpd 초과). _lock 보유 상태 가정."""
        self._ensure_groq_model(model)
        if datetime.now() >= self._tpd_reset_model[model]:  # 일간 리셋
            self._tpd_used_model[model] = 0
            self._gr_req_model[model] = 0
            self._tpd_reset_model[model] = datetime.now() + timedelta(hours=24)
            self._tpd_exhausted_model[model] = False
        if self._tpd_exhausted_model[model]:
            return True
        lim = self._groq_model_limits(model)
        rpd, tpd = lim.get("rpd"), lim.get("tpd")
        if rpd is not None and self._gr_req_model[model] + 1 > rpd:
            return True
        if tpd is not None and self._tpd_used_model[model] + required_tokens > tpd:
            return True
        return False

    def active_groq_model(self, models, required_tokens: int = 15000):
        """우선순위 순 models 중 이번 호출을 감당할 여유(rpd·tpd)가 있는 첫 모델을 반환.
        모두 소진이면 None. (앞 모델 소진 시 다음 모델로 전환하는 캐스케이드의 핵심.)"""
        with self._lock:
            for model in models:
                if not self._groq_model_exhausted(model, required_tokens):
                    return model
            return None

    def mark_groq_exhausted(self, model: str) -> None:
        """모델의 일일 한도 소진 마킹 (429 수신 시)."""
        with self._lock:
            self._ensure_groq_model(model)
            self._tpd_exhausted_model[model] = True
            logger.warning(f"🚫 {model} 일일 한도 소진 마킹 — 다음 모델/SKIP로 전환")

    def check_and_wait(self, api_name: str) -> bool:
        """API 호출 전 반드시 호출. Lock으로 동시 접근 차단."""
        if api_name not in self.limits:
            logger.warning(f"알 수 없는 API: {api_name}, Rate Limit 적용 안 됨")
            return True
        
        with self._lock:
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
                
                logger.warning(
                    f"⚠️ {api_name} Rate Limit 도달! "
                    f"({info.used}/{info.limit}) "
                    f"{wait_time:.0f}초 대기 중..."
                )
                time.sleep(wait_time + 1)
                self.stats["total_waits"] += 1
                self.stats["total_wait_time"] += wait_time
                info.used = 0
                info.reset_at = datetime.now() + timedelta(seconds=info.window_seconds)
            
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
    
    def record_call(self, api_name: str, tokens_used: int = 0, model: Optional[str] = None):
        """API 호출 기록 (Thread-Safe). tokens_used가 있으면 TPM/TPD도 업데이트.
        model이 주어지면(Groq) 해당 모델의 TPD 버킷에 누적한다."""
        if api_name not in self.limits:
            return
        with self._lock:
            info = self.limits[api_name]
            info.used += 1
            info.last_call_at = time.time()
            self.stats["total_calls"] += 1
            logger.debug(f"{api_name} 호출 기록: {info.used}/{info.limit} ({info.usage_percent:.1f}%)")

            # RPD 트래킹 (일 윈도우) — 토큰과 무관하게 호출 1건마다 누적 (Gemma는 TPM 무제한)
            if api_name in self._rpd_limits:
                now = datetime.now()
                if now >= self._rpd_reset_at[api_name]:
                    self._rpd_used[api_name] = 0
                    self._rpd_reset_at[api_name] = now + timedelta(hours=24)
                    logger.info(f"🔄 {api_name} RPD 리셋")
                self._rpd_used[api_name] += 1
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

            # Groq 모델별 일일 사용량 (요청 수 + 토큰) — model이 주어진 Groq 호출만
            if model:
                self._ensure_groq_model(model)
                now = datetime.now()
                if now >= self._tpd_reset_model[model]:
                    self._tpd_used_model[model] = 0
                    self._gr_req_model[model] = 0
                    self._tpd_reset_model[model] = now + timedelta(hours=24)
                    self._tpd_exhausted_model[model] = False
                    logger.info(f"🔄 {model} 일일 카운터 리셋")

                self._gr_req_model[model] += 1
                self._tpd_used_model[model] += tokens_used

                lim = self._groq_model_limits(model)
                rpd, tpd = lim.get("rpd"), lim.get("tpd")
                if rpd:
                    pct = self._gr_req_model[model] / rpd * 100
                    if pct >= 90:
                        logger.warning(f"⚠️ {model} RPD 90% 도달! ({self._gr_req_model[model]:,}/{rpd:,})")
                if tpd:
                    pct = self._tpd_used_model[model] / tpd * 100
                    logger.debug(f"{model} TPD: {self._tpd_used_model[model]:,}/{tpd:,} ({pct:.1f}%)")
                    if pct >= 90:
                        logger.warning(f"⚠️ {model} TPD 90% 도달! ({self._tpd_used_model[model]:,}/{tpd:,})")

    def is_tpd_exhausted(self, model: str, required_tokens: int = 15000) -> bool:
        """특정 Groq 모델이 다음 호출을 감당 못 하는지(rpd 또는 tpd 소진) 확인."""
        with self._lock:
            return self._groq_model_exhausted(model, required_tokens)

    def is_rpd_exhausted(self, api_name: str) -> bool:
        """일간 요청 한도(RPD) 추적 대상 API의 소진 여부. 미추적 API는 False."""
        with self._lock:
            limit = self._rpd_limits.get(api_name)
            if limit is None:
                return False
            if datetime.now() >= self._rpd_reset_at.get(api_name, datetime.min):
                return False  # 일간 윈도우 경과 → 다음 record_call에서 리셋됨
            return self._rpd_used.get(api_name, 0) >= limit

    def mark_rpd_exhausted(self, api_name: str) -> None:
        """RPD 소진 마킹 (일간 quota 429 수신 시 — 대기 무의미, 즉시 스킵 전환)."""
        with self._lock:
            if api_name in self._rpd_limits:
                self._rpd_used[api_name] = self._rpd_limits[api_name]
                logger.warning(f"🚫 {api_name} 일일 한도(RPD) 소진 마킹 — SKIP 전환")

    def handle_429(self, api_name: str, retry_after: Optional[float] = None,
                   error_message: str = "", model: Optional[str] = None):
        """429 Too Many Requests 대응 (Thread-Safe). TPD 소진이면 대기 대신 즉시 마킹."""
        with self._lock:
            self.stats["rate_limit_hits"] += 1

            # 일일 한도(TPD 토큰 or RPD 요청) 소진 429 → 대기 무의미, 해당 모델 즉시 소진 마킹
            _msg = error_message.lower()
            if model and ("tokens per day" in _msg or "tpd" in _msg
                          or "requests per day" in _msg or "rpd" in _msg or "per day" in _msg):
                self._ensure_groq_model(model)
                self._tpd_exhausted_model[model] = True
                logger.warning(
                    f"🚫 {model} 일일 한도 소진 429! 다음 모델/SKIP로 전환 "
                    f"(누적 429: {self.stats['rate_limit_hits']}회)"
                )
                self.stats["total_waits"] += 1
                return

            if api_name not in self.limits:
                wait_time = retry_after if retry_after else 60
                logger.warning(f"⚠️ {api_name} 429 수신, {wait_time:.0f}초 대기")
                time.sleep(wait_time)
                return

            info = self.limits[api_name]
            info.used = info.limit

            if retry_after:
                wait_time = retry_after + 2
            else:
                wait_time = info.time_until_reset
                if wait_time <= 0:
                    wait_time = info.window_seconds

            logger.warning(
                f"⚠️ {api_name} 429 수신! {wait_time:.0f}초 대기 "
                f"(누적 429: {self.stats['rate_limit_hits']}회)"
            )

        time.sleep(wait_time)

        with self._lock:
            self.stats["total_waits"] += 1
            self.stats["total_wait_time"] += wait_time
            info = self.limits.get(api_name)
            if info:
                info.used = 0
                info.reset_at = datetime.now() + timedelta(seconds=info.window_seconds)
    
    @staticmethod
    def parse_retry_after(error_message: str) -> Optional[float]:
        """
        에러 메시지에서 대기 시간 추출

        지원 형식:
        - "try again in 10m3.072s" → 603.072초
        - "try again in 45.5s" → 45.5초
        - "try again in 2m" → 120초
        - "Retry-After: 60" → 60초
        """
        msg = str(error_message)

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
    
    def get_status(self, api_name: Optional[str] = None) -> Dict:
        """현재 상태 조회"""
        with self._lock:
            if api_name:
                if api_name not in self.limits:
                    return {}
                info = self.limits[api_name]
                return {
                    "api": api_name, "used": info.used, "limit": info.limit,
                    "remaining": info.remaining,
                    "usage_percent": round(info.usage_percent, 1),
                    "reset_in": round(info.time_until_reset, 0)
                }
            return {
                "apis": {
                    name: {"used": info.used, "limit": info.limit,
                           "remaining": info.remaining, "usage": f"{info.usage_percent:.1f}%"}
                    for name, info in self.limits.items()
                },
                "stats": dict(self.stats)
            }
    
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
        # Groq 모델별 일일 사용량 요약 (모델마다 RPD 또는 TPD 기준)
        for model in self._tpd_used_model:
            req = self._gr_req_model.get(model, 0)
            tok = self._tpd_used_model.get(model, 0)
            if req == 0 and not self._tpd_exhausted_model.get(model, False):
                continue
            lim = self._groq_model_limits(model)
            rpd, tpd = lim.get("rpd"), lim.get("tpd")
            exhausted = " (EXHAUSTED)" if self._tpd_exhausted_model.get(model, False) else ""
            if rpd:  # RPD 기준 모델(현재 미사용 — tpd 기준만)
                pct = req / rpd * 100
                logger.info(f"  {(model[:14]+' RPD'):18s}: {req:,}/{rpd:,} [{self._create_usage_bar(pct)}] {pct:5.1f}%{exhausted}")
            if tpd:  # 추론형: 토큰 기준
                pct = tok / tpd * 100
                logger.info(f"  {(model[:14]+' TPD'):18s}: {tok:,}/{tpd:,} [{self._create_usage_bar(pct)}] {pct:5.1f}%{exhausted}")
        # RPD 요약 (Gemma 일간 요청 수)
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