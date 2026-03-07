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
            # GitHub Search API: 인증 사용자 10회/분
            "github_search": RateLimitInfo(
                limit=8,
                window_seconds=60,
                min_interval=7.0
            ),
            # Groq Free Tier: RPM 30 + TPM 8000
            "groq": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=5.0
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
            # Gemini Free Tier: 30 RPM, 15K TPM
            "gemini": RateLimitInfo(
                limit=25,
                window_seconds=60,
                min_interval=2.5
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

        # TPD (Tokens Per Day) 트래킹 — Groq 일간 토큰 한도 관리
        self._tpd_limits: Dict[str, int] = {
            "groq": 200_000,  # Free Tier: 200K TPD
        }
        self._tpd_used: Dict[str, int] = {}
        self._tpd_reset_at: Dict[str, datetime] = {}
        self._tpd_exhausted: Dict[str, bool] = {}
        for api in self._tpd_limits:
            self._tpd_used[api] = 0
            self._tpd_reset_at[api] = datetime.now() + timedelta(hours=24)
            self._tpd_exhausted[api] = False

        logger.info("Rate Limit Manager v3.1 초기화 완료 (Thread-Safe + TPD 트래킹)")
    
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
        
        return True
    
    def record_call(self, api_name: str, tokens_used: int = 0):
        """API 호출 기록 (Thread-Safe). tokens_used가 있으면 TPD도 업데이트."""
        if api_name not in self.limits:
            return
        with self._lock:
            info = self.limits[api_name]
            info.used += 1
            info.last_call_at = time.time()
            self.stats["total_calls"] += 1
            logger.debug(f"{api_name} 호출 기록: {info.used}/{info.limit} ({info.usage_percent:.1f}%)")

            # TPD 트래킹
            if tokens_used > 0 and api_name in self._tpd_limits:
                now = datetime.now()
                if now >= self._tpd_reset_at[api_name]:
                    self._tpd_used[api_name] = 0
                    self._tpd_reset_at[api_name] = now + timedelta(hours=24)
                    self._tpd_exhausted[api_name] = False
                    logger.info(f"🔄 {api_name} TPD 리셋")

                self._tpd_used[api_name] += tokens_used
                tpd_limit = self._tpd_limits[api_name]
                tpd_remaining = tpd_limit - self._tpd_used[api_name]
                tpd_pct = (self._tpd_used[api_name] / tpd_limit) * 100

                logger.debug(f"{api_name} TPD: {self._tpd_used[api_name]:,}/{tpd_limit:,} ({tpd_pct:.1f}%, 잔여 {tpd_remaining:,})")

                if tpd_pct >= 90:
                    logger.warning(f"⚠️ {api_name} TPD 90% 도달! ({self._tpd_used[api_name]:,}/{tpd_limit:,})")

    def is_tpd_exhausted(self, api_name: str, required_tokens: int = 15000) -> bool:
        """TPD 잔량이 부족한지 확인. required_tokens는 다음 호출에 필요한 예상 토큰."""
        with self._lock:
            if api_name not in self._tpd_limits:
                return False

            # 429로 TPD 소진 감지된 경우
            if self._tpd_exhausted.get(api_name, False):
                return True

            remaining = self._tpd_limits[api_name] - self._tpd_used[api_name]
            return remaining < required_tokens

    def mark_tpd_exhausted(self, api_name: str):
        """429 TPD 에러 수신 시 소진 상태로 마킹"""
        with self._lock:
            self._tpd_exhausted[api_name] = True
            logger.warning(f"🚫 {api_name} TPD 소진 마킹 — 이번 실행의 나머지 Groq 호출 SKIP")
    
    def handle_429(self, api_name: str, retry_after: Optional[float] = None, error_message: str = ""):
        """429 Too Many Requests 대응 (Thread-Safe). TPD 소진이면 대기 대신 즉시 마킹."""
        with self._lock:
            self.stats["rate_limit_hits"] += 1

            # TPD(일간 토큰) 소진인 경우 → 대기해도 의미 없음, 즉시 소진 마킹
            if "tokens per day" in error_message.lower() or "tpd" in error_message.lower():
                self._tpd_exhausted[api_name] = True
                logger.warning(
                    f"🚫 {api_name} TPD 소진 429! 남은 Groq 호출 SKIP "
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
        # TPD 요약
        for api, limit in self._tpd_limits.items():
            used = self._tpd_used.get(api, 0)
            if used > 0:
                tpd_pct = (used / limit) * 100
                tpd_bar = self._create_usage_bar(tpd_pct)
                exhausted = " (EXHAUSTED)" if self._tpd_exhausted.get(api, False) else ""
                logger.info(
                    f"  {api + ' TPD':18s}: {used:,}/{limit:,} "
                    f"[{tpd_bar}] {tpd_pct:5.1f}%{exhausted}"
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