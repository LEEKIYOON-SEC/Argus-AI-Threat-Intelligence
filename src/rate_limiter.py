import time
import threading
import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from logger import logger


def is_transient_gemini_error(msg: str) -> bool:
    return bool(re.search(r'\b(500|503)\b', msg)) or any(t in msg for t in (
        "INTERNAL", "UNAVAILABLE", "high demand", "overloaded", "try again"
    ))


_ERR_LABEL = {"rate": "분당한도(429)", "rpd": "일일한도(429)",
              "transient": "일시장애(5xx·타임아웃)", "other": "기타"}


def gemini_error_kind(msg: str) -> str:
    low = msg.lower()
    if "429" in msg or "resource_exhausted" in low or "resource exhausted" in low:
        if any(t in low for t in ("perday", "per day", "per-day", "daily")):
            kind = "rpd"
        else:
            kind = "rate"
    elif is_transient_gemini_error(msg):
        kind = "transient"
    else:
        kind = "other"
    rate_limit_manager.note_error(kind)
    return kind


def gemini_backoff(kind: str, attempt: int, msg: str, manager=None) -> float:
    if kind == "rate":
        hinted = (manager or rate_limit_manager).parse_retry_after(msg)
        return min(hinted if hinted else 8.0 * attempt, 30.0)
    return 2.0 * attempt


@dataclass
class RateLimitInfo:
    limit: int
    used: int = 0
    reset_at: datetime = field(default_factory=datetime.now)
    window_seconds: int = 3600
    min_interval: float = 0.0
    last_call_at: float = 0.0
    next_slot_at: float = 0.0


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
            "gemini_35": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            "gemini_31": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            "gemma_31b": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
            ),
            "gemma_26b": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
            ),
            "analysis_35": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            "analysis_31": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            "vulncheck": RateLimitInfo(
                limit=40,
                window_seconds=60,
                min_interval=1.5
            ),
            "ruleset_download": RateLimitInfo(
                limit=20,
                window_seconds=3600,
                min_interval=2.0
            )
        }
        
        self._lock = threading.Lock()
        self._skip_warned_at: Dict[str, datetime] = {}

        self.stats = {
            "total_calls": 0,
            "total_waits": 0,
            "total_wait_time": 0.0,
            "rate_limit_hits": 0
        }
        self._errors: Dict[str, int] = {}

        self._tpm_limits: Dict[str, int] = {
            "gemini_35": 250_000,
            "gemini_31": 250_000,
            "gemma_31b": 16_000,
            "gemma_26b": 16_000,
            "analysis_35": 250_000,
            "analysis_31": 250_000,
        }
        self._tpm_reserve: Dict[str, int] = {
            "gemini_35": 25_000,
            "gemini_31": 25_000,
            "gemma_31b": 4_000,
            "gemma_26b": 4_000,
            "analysis_35": 25_000,
            "analysis_31": 25_000,
        }
        self._tpm_used: Dict[str, int] = {api: 0 for api in self._tpm_limits}
        self._tpm_reset_at: Dict[str, datetime] = {
            api: datetime.now() + timedelta(seconds=60) for api in self._tpm_limits
        }

        self._rpd_limits: Dict[str, int] = {
            "gemini_35": 250,
            "gemini_31": 250,
            "gemma_31b": 14_400,
            "gemma_26b": 14_400,
            "analysis_35": 250,
            "analysis_31": 250,
        }
        self._rpd_used: Dict[str, int] = {api: 0 for api in self._rpd_limits}
        self._rpd_buckets: Dict[str, Dict[str, int]] = {api: {} for api in self._rpd_limits}
        self._rpd_skip_warned: Dict[str, bool] = {}

        logger.info("Rate Limit Manager 초기화 완료 (Thread-Safe · RPM/TPM/RPD 모델별 추적)")


    def check_and_wait(self, api_name: str, max_wait: Optional[float] = None) -> bool:
        if api_name not in self.limits:
            logger.warning(f"알 수 없는 API: {api_name}, Rate Limit 적용 안 됨")
            return True

        with self._lock:
            rpd_limit = self._rpd_limits.get(api_name)
            if rpd_limit and self._rolling_sum(self._rpd_buckets, api_name) >= rpd_limit:
                if not self._rpd_skip_warned.get(api_name):
                    logger.warning(f"⏭️ {api_name} 일일 요청 한도(RPD {rpd_limit:,}) 소진 — "
                                   f"이번 실행의 후속 호출은 SKIP (24h 롤링이라 저절로 풀린다)")
                    self._rpd_skip_warned[api_name] = True
                return False

            info = self.limits[api_name]
            now = datetime.now()
            if now >= info.reset_at:
                info.used = 0
                info.reset_at = now + timedelta(seconds=info.window_seconds)

            now_t = time.time()
            spacing = max(0.0, max(now_t, info.next_slot_at) - now_t)

            window_wait = 0.0
            if info.is_exhausted:
                window_wait = info.time_until_reset or info.window_seconds

            usage = info.usage_percent
            throttle = 0.0
            if usage >= 90:
                throttle = info.min_interval * 2 if info.min_interval > 0 else 5.0
            elif usage >= 80:
                throttle = info.min_interval if info.min_interval > 0 else 2.0

            tpm_wait = 0.0
            if api_name in self._tpm_limits:
                if now >= self._tpm_reset_at[api_name]:
                    self._tpm_used[api_name] = 0
                    self._tpm_reset_at[api_name] = now + timedelta(seconds=60)
                if (self._tpm_used[api_name] + self._tpm_reserve.get(api_name, 0)
                        > self._tpm_limits[api_name]):
                    tpm_wait = max(0.0,
                                   (self._tpm_reset_at[api_name] - now).total_seconds())

            total = spacing + window_wait + throttle + tpm_wait
            if max_wait is not None and total > max_wait:
                last_warn = self._skip_warned_at.get(api_name)
                if last_warn is None or last_warn < now - timedelta(seconds=info.window_seconds):
                    logger.warning(f"⏭️ {api_name} 대기 {total:.0f}초가 상한 {max_wait:.0f}초를 "
                                   f"넘는다 — 대기 대신 SKIP")
                    self._skip_warned_at[api_name] = now
                else:
                    logger.debug(f"{api_name} 대기 상한 초과 SKIP")
                return False

            if info.min_interval > 0:
                info.next_slot_at = max(now_t, info.next_slot_at) + info.min_interval
            info.used += 1
            info.last_call_at = now_t
            if window_wait:
                logger.warning(f"⚠️ {api_name} Rate Limit 도달! "
                               f"({info.used}/{info.limit}) {window_wait:.0f}초 대기 중...")
            elif throttle and usage >= 90:
                logger.warning(f"⚠️ {api_name} 사용률 높음: {usage:.1f}% "
                               f"({info.remaining}개 남음) — {throttle:.1f}초 추가 대기")
            if tpm_wait:
                logger.warning(f"⏳ {api_name} TPM 예약 한도 근접 "
                               f"({self._tpm_used[api_name]}/{self._tpm_limits[api_name]}), "
                               f"{tpm_wait:.0f}초 대기(분 리셋)")

        if total > 0:
            time.sleep(total + (1.0 if window_wait else 0.0))
            with self._lock:
                self.stats["total_waits"] += 1
                self.stats["total_wait_time"] += total
                if window_wait:
                    info = self.limits[api_name]
                    info.used = 0
                    info.reset_at = datetime.now() + timedelta(seconds=info.window_seconds)
                if tpm_wait:
                    self._tpm_used[api_name] = 0
                    self._tpm_reset_at[api_name] = (datetime.now()
                                                    + timedelta(seconds=60))
        return True


    def note_error(self, kind: str) -> None:
        with self._lock:
            self._errors[kind] = self._errors.get(kind, 0) + 1
            if kind in ("rate", "rpd"):
                self.stats["rate_limit_hits"] += 1


    def record_call(self, api_name: str, tokens_used: int = 0):
        if api_name not in self.limits:
            return
        with self._lock:
            info = self.limits[api_name]
            self.stats["total_calls"] += 1
            logger.debug(f"{api_name} 호출 기록: {info.used}/{info.limit} ({info.usage_percent:.1f}%)")

            key = self._rpd_bucket_key()
            if api_name in self._rpd_limits:
                buckets = self._rpd_buckets[api_name]
                buckets[key] = buckets.get(key, 0) + 1
                self._rpd_used[api_name] = self._rolling_sum(self._rpd_buckets, api_name)
                rpd_limit = self._rpd_limits[api_name]
                if rpd_limit:
                    rpd_pct = (self._rpd_used[api_name] / rpd_limit) * 100
                    logger.debug(f"{api_name} RPD: {self._rpd_used[api_name]:,}/{rpd_limit:,} ({rpd_pct:.1f}%)")
                    if rpd_pct >= 90:
                        logger.warning(f"⚠️ {api_name} RPD 90% 도달! ({self._rpd_used[api_name]:,}/{rpd_limit:,})")

            if tokens_used > 0 and api_name in self._tpm_limits:
                now = datetime.now()
                if now >= self._tpm_reset_at[api_name]:
                    self._tpm_used[api_name] = 0
                    self._tpm_reset_at[api_name] = now + timedelta(seconds=60)
                self._tpm_used[api_name] += tokens_used


    @staticmethod
    def _rpd_bucket_key(when: Optional[datetime] = None) -> str:
        return (when or datetime.now(timezone.utc)).astimezone(
            timezone.utc).strftime("%Y-%m-%dT%H")


    @staticmethod
    def _rolling_sum(store: Dict[str, Dict[str, int]], api_name: str) -> int:
        buckets = store.get(api_name)
        if not buckets:
            return 0
        cutoff = RateLimitManager._rpd_bucket_key(
            datetime.now(timezone.utc) - timedelta(hours=23))
        for key in [k for k in buckets if k < cutoff]:
            del buckets[key]
        return sum(buckets.values())


    def import_rpd_state(self, state: Dict) -> None:
        if not isinstance(state, dict):
            return
        section = state.get("rpd") if ("rpd" in state or "tpd" in state) else state
        with self._lock:
            for api, buckets in (section or {}).items():
                if api not in self._rpd_buckets or not isinstance(buckets, dict):
                    continue
                self._rpd_buckets[api] = {str(k): int(v) for k, v in buckets.items()
                                          if isinstance(v, (int, float)) and int(v) > 0}
                used = self._rolling_sum(self._rpd_buckets, api)
                self._rpd_used[api] = used
                if used:
                    logger.info(f"🔁 {api} RPD 이월: 최근 24h {used:,}"
                                f"/{self._rpd_limits[api]:,}")


    def export_rpd_state(self) -> Dict[str, Dict[str, int]]:
        with self._lock:
            out: Dict[str, Dict[str, int]] = {}
            for api in self._rpd_buckets:
                self._rolling_sum(self._rpd_buckets, api)
                if self._rpd_buckets[api]:
                    out[api] = dict(self._rpd_buckets[api])
            return out


    def rpd_status(self, api_name: str) -> Tuple[int, int]:
        with self._lock:
            return (self._rolling_sum(self._rpd_buckets, api_name),
                    self._rpd_limits.get(api_name) or 0)


    def daily_headroom(self, api_name: str) -> int:
        with self._lock:
            limit = self._rpd_limits.get(api_name) or 0
            return max(0, limit - self._rolling_sum(self._rpd_buckets, api_name))


    def minute_token_headroom(self, api_name: str) -> int:
        with self._lock:
            limit = self._tpm_limits.get(api_name) or 0
            return max(0, limit - self._tpm_reserve.get(api_name, 0))


    def is_rpd_exhausted(self, api_name: str) -> bool:
        with self._lock:
            limit = self._rpd_limits.get(api_name) or 0
            return bool(limit) and self._rolling_sum(self._rpd_buckets, api_name) >= limit


    def mark_rpd_exhausted(self, api_name: str) -> None:
        with self._lock:
            limit = self._rpd_limits.get(api_name) or 0
            if not limit:
                return
            shortfall = max(0, limit - self._rolling_sum(self._rpd_buckets, api_name))
            if shortfall:
                key = self._rpd_bucket_key()
                self._rpd_buckets[api_name][key] = (
                    self._rpd_buckets[api_name].get(key, 0) + shortfall)
            self._rpd_used[api_name] = self._rolling_sum(self._rpd_buckets, api_name)
            logger.warning(f"🚫 {api_name} 일일 한도(RPD) 소진 마킹 — SKIP 전환")


    @staticmethod
    def parse_retry_after(error_message: str) -> Optional[float]:
        msg = str(error_message)

        match = re.search(r'retryDelay["\']?\s*[:=]\s*["\']?(?:(\d+)m)?(\d+\.?\d*)s',
                          msg, re.IGNORECASE)
        if match:
            return int(match.group(1) or 0) * 60 + float(match.group(2))

        match = re.search(r'(?:retry|try again) in (\d+)m(\d+\.?\d*)s', msg, re.IGNORECASE)
        if match:
            minutes = int(match.group(1))
            seconds = float(match.group(2))
            return minutes * 60 + seconds

        match = re.search(r'(?:retry|try again) in (\d+)m\b', msg, re.IGNORECASE)
        if match:
            return int(match.group(1)) * 60.0

        match = re.search(r'(?:retry|try again) in (\d+\.?\d*)s', msg, re.IGNORECASE)
        if match:
            return float(match.group(1))

        match = re.search(r'Retry-After:\s*(\d+)', msg)
        if match:
            return float(match.group(1))

        return None


    def print_summary(self):
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
        for api in self._rpd_buckets:
            used = self._rolling_sum(self._rpd_buckets, api)
            if used <= 0:
                continue
            limit = self._rpd_limits[api]
            pct = (used / limit) * 100
            logger.info(f"  {api + ' RPD':18s}: {used:,}/{limit:,} "
                        f"[{self._create_usage_bar(pct)}] {pct:5.1f}%")
        logger.info("-" * 60)
        logger.info(f"  총 API 호출: {self.stats['total_calls']}회")
        logger.info(f"  Rate Limit 대기: {self.stats['total_waits']}회")
        logger.info(f"  429 응답 수신: {self.stats['rate_limit_hits']}회")
        logger.info(f"  총 대기 시간: {self.stats['total_wait_time']:.1f}초")
        if self._errors:
            breakdown = " · ".join(f"{_ERR_LABEL.get(k, k)} {v}"
                                   for k, v in sorted(self._errors.items()))
            logger.info(f"  API 오류 내역: {breakdown}")
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
