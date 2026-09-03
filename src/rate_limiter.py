import os
import time
import threading
import re
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from logger import logger


def _env_int(name: str, default: int) -> int:
    """한도는 AI Studio 에서만 확인할 수 있으므로 코드 수정 없이 바꿀 수 있게 둔다.

    0 은 '한도 없음(추적만 안 함)'을 뜻한다 — TPD 처럼 값이 공개되지 않는 항목의 기본값.
    """
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning(f"{name}={raw!r} 를 숫자로 못 읽었다 → 기본값 {default:,} 사용")
        return default

def is_transient_gemini_error(msg: str) -> bool:
    return bool(re.search(r'\b(500|503)\b', msg)) or any(t in msg for t in (
        "INTERNAL", "UNAVAILABLE", "high demand", "overloaded", "try again"
    ))


def gemini_error_kind(msg: str) -> str:
    low = msg.lower()
    if "429" in msg or "resource_exhausted" in low or "resource exhausted" in low:
        if any(t in low for t in ("perday", "per day", "per-day", "daily")):
            return "rpd"
        return "rate"
    if is_transient_gemini_error(msg):
        return "transient"
    return "other"


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
            "gemini": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
            ),
            "gemini_fb": RateLimitInfo(
                limit=30,
                window_seconds=60,
                min_interval=2.0
            ),
            "gemini_analysis": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            "gemini_analysis_fb": RateLimitInfo(
                limit=15,
                window_seconds=60,
                min_interval=4.0
            ),
            "nvd": RateLimitInfo(
                limit=40,
                window_seconds=30,
                min_interval=1.0
            ),
            "vulncheck": RateLimitInfo(
                limit=40,
                window_seconds=60,
                min_interval=1.5
            ),
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
        self._skip_warned_at: Dict[str, datetime] = {}

        self.stats = {
            "total_calls": 0,
            "total_waits": 0,
            "total_wait_time": 0.0,
            "rate_limit_hits": 0
        }

        self._tpm_limits: Dict[str, int] = {
            "gemini": 16_000,
            "gemini_fb": 16_000,
        }
        self._tpm_reserve: Dict[str, int] = {
            "gemini": 4_000,
            "gemini_fb": 4_000,
        }
        self._tpm_used: Dict[str, int] = {api: 0 for api in self._tpm_limits}
        self._tpm_reset_at: Dict[str, datetime] = {
            api: datetime.now() + timedelta(seconds=60) for api in self._tpm_limits
        }

        self._rpd_limits: Dict[str, int] = {
            "gemini": _env_int("ARGUS_RPD_GEMINI", 14_400),
            "gemini_fb": _env_int("ARGUS_RPD_GEMINI_FB", 14_400),
            "gemini_analysis": _env_int("ARGUS_RPD_ANALYSIS", 500),
            "gemini_analysis_fb": _env_int("ARGUS_RPD_ANALYSIS_FB", 500),
        }
        # TPD — 예전에는 추적하지 않았다. RPD 는 남았는데 토큰만 소진되면 429 를 받고
        # 그때서야 알게 된다. RPD 와 같은 시간별 버킷(최근 24h 롤링)으로 세므로
        # 실행 사이에 이월되고, 24시간이 지나면 저절로 풀린다.
        self._tpd_limits: Dict[str, int] = {
            "gemini": _env_int("ARGUS_TPD_GEMINI", 0),
            "gemini_fb": _env_int("ARGUS_TPD_GEMINI_FB", 0),
            "gemini_analysis": _env_int("ARGUS_TPD_ANALYSIS", 0),
            "gemini_analysis_fb": _env_int("ARGUS_TPD_ANALYSIS_FB", 0),
        }
        self._rpd_used: Dict[str, int] = {api: 0 for api in self._rpd_limits}
        self._rpd_buckets: Dict[str, Dict[str, int]] = {api: {} for api in self._rpd_limits}
        self._tpd_buckets: Dict[str, Dict[str, int]] = {api: {} for api in self._tpd_limits}
        self._rpd_skip_warned: Dict[str, bool] = {}
        self._tpd_skip_warned: Dict[str, bool] = {}

        logger.info("Rate Limit Manager 초기화 완료 (Thread-Safe · RPM/TPM/RPD 모델별 추적)")

    def check_and_wait(self, api_name: str, max_wait: Optional[float] = None) -> bool:
        if api_name not in self.limits:
            logger.warning(f"알 수 없는 API: {api_name}, Rate Limit 적용 안 됨")
            return True

        exhausted_wait = 0.0
        with self._lock:
            rpd_limit = self._rpd_limits.get(api_name)
            if rpd_limit and self._rolling_sum(self._rpd_buckets, api_name) >= rpd_limit:
                if not self._rpd_skip_warned.get(api_name):
                    logger.warning(f"⏭️ {api_name} 일일 요청 한도(RPD {rpd_limit:,}) 소진 — "
                                   f"이번 실행의 후속 호출은 SKIP (24h 롤링이라 저절로 풀린다)")
                    self._rpd_skip_warned[api_name] = True
                return False

            tpd_limit = self._tpd_limits.get(api_name)
            if tpd_limit and self._rolling_sum(self._tpd_buckets, api_name) >= tpd_limit:
                if not self._tpd_skip_warned.get(api_name):
                    logger.warning(f"⏭️ {api_name} 일일 토큰 한도(TPD {tpd_limit:,}) 소진 — "
                                   f"이번 실행의 후속 호출은 SKIP (24h 롤링이라 저절로 풀린다)")
                    self._tpd_skip_warned[api_name] = True
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
        if api_name not in self.limits:
            return
        with self._lock:
            info = self.limits[api_name]
            info.used += 1
            info.last_call_at = time.time()
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

            if tokens_used > 0 and api_name in self._tpd_buckets:
                tbuckets = self._tpd_buckets[api_name]
                tbuckets[key] = tbuckets.get(key, 0) + int(tokens_used)
                tpd_limit = self._tpd_limits.get(api_name) or 0
                if tpd_limit:
                    used = self._rolling_sum(self._tpd_buckets, api_name)
                    if used / tpd_limit >= 0.9:
                        logger.warning(f"⚠️ {api_name} TPD 90% 도달! ({used:,}/{tpd_limit:,})")

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
        """최근 24시간 롤링 합. 지나간 시간 버킷은 지운다 = '한도 리셋'이 저절로 된다."""
        buckets = store.get(api_name)
        if not buckets:
            return 0
        cutoff = RateLimitManager._rpd_bucket_key(
            datetime.now(timezone.utc) - timedelta(hours=23))
        for key in [k for k in buckets if k < cutoff]:
            del buckets[key]
        return sum(buckets.values())

    def _rpd_rolling_sum(self, api_name: str) -> int:
        return self._rolling_sum(self._rpd_buckets, api_name)

    def import_rpd_state(self, state: Dict) -> None:
        """예전 모양({api: buckets})과 새 모양({'rpd': …, 'tpd': …}) 둘 다 받는다."""
        if not isinstance(state, dict):
            return
        if "rpd" in state or "tpd" in state:
            sections = {"rpd": state.get("rpd") or {}, "tpd": state.get("tpd") or {}}
        else:
            sections = {"rpd": state, "tpd": {}}

        with self._lock:
            for kind, store, limits in (("rpd", self._rpd_buckets, self._rpd_limits),
                                        ("tpd", self._tpd_buckets, self._tpd_limits)):
                for api, buckets in (sections[kind] or {}).items():
                    if api not in store or not isinstance(buckets, dict):
                        continue
                    store[api] = {str(k): int(v) for k, v in buckets.items()
                                  if isinstance(v, (int, float)) and int(v) > 0}
                    used = self._rolling_sum(store, api)
                    if kind == "rpd":
                        self._rpd_used[api] = used
                    if used:
                        limit = limits.get(api) or 0
                        logger.info(f"🔁 {api} {kind.upper()} 이월: 최근 24h {used:,}"
                                    + (f"/{limit:,}" if limit else " (한도 미설정)"))

    def export_rpd_state(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        with self._lock:
            out: Dict[str, Dict[str, Dict[str, int]]] = {"rpd": {}, "tpd": {}}
            for kind, store in (("rpd", self._rpd_buckets), ("tpd", self._tpd_buckets)):
                for api in store:
                    self._rolling_sum(store, api)
                    if store[api]:
                        out[kind][api] = dict(store[api])
            return {k: v for k, v in out.items() if v}

    def rpd_status(self, api_name: str) -> Tuple[int, int]:
        with self._lock:
            return (self._rolling_sum(self._rpd_buckets, api_name),
                    self._rpd_limits.get(api_name) or 0)

    def tpd_status(self, api_name: str) -> Tuple[int, int]:
        with self._lock:
            return (self._rolling_sum(self._tpd_buckets, api_name),
                    self._tpd_limits.get(api_name) or 0)

    def daily_headroom(self, api_name: str) -> Tuple[Optional[int], Optional[int]]:
        """(남은 요청 수, 남은 토큰 수). 한도가 설정 안 됐으면 None = 제한 없음."""
        with self._lock:
            rpd = self._rpd_limits.get(api_name) or 0
            tpd = self._tpd_limits.get(api_name) or 0
            return (max(0, rpd - self._rolling_sum(self._rpd_buckets, api_name)) if rpd else None,
                    max(0, tpd - self._rolling_sum(self._tpd_buckets, api_name)) if tpd else None)

    def is_rpd_exhausted(self, api_name: str) -> bool:
        """RPD 든 TPD 든 하나라도 소진이면 True — 호출부는 '오늘은 끝'으로 읽으면 된다."""
        with self._lock:
            rpd = self._rpd_limits.get(api_name) or 0
            tpd = self._tpd_limits.get(api_name) or 0
            if rpd and self._rolling_sum(self._rpd_buckets, api_name) >= rpd:
                return True
            return bool(tpd) and self._rolling_sum(self._tpd_buckets, api_name) >= tpd

    def mark_rpd_exhausted(self, api_name: str) -> None:
        """API 가 직접 일일 한도 초과를 알려 왔다 — 우리 카운터를 한도까지 채워 맞춘다.

        RPD 든 TPD 든 응답만 보고는 어느 쪽인지 모를 때가 많아 둘 다 채운다. 어차피 둘 다
        24시간 롤링이라 다음 날 저절로 풀린다.
        """
        with self._lock:
            key = self._rpd_bucket_key()
            for store, limits in ((self._rpd_buckets, self._rpd_limits),
                                  (self._tpd_buckets, self._tpd_limits)):
                limit = limits.get(api_name) or 0
                if not limit:
                    continue
                shortfall = max(0, limit - self._rolling_sum(store, api_name))
                if shortfall:
                    store[api_name][key] = store[api_name].get(key, 0) + shortfall
            if api_name in self._rpd_limits:
                self._rpd_used[api_name] = self._rolling_sum(self._rpd_buckets, api_name)
            logger.warning(f"🚫 {api_name} 일일 한도 소진 마킹 — SKIP 전환 (24h 뒤 자동 해제)")

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
        for label, store, limits in (("RPD", self._rpd_buckets, self._rpd_limits),
                                     ("TPD", self._tpd_buckets, self._tpd_limits)):
            for api in store:
                used = self._rolling_sum(store, api)
                if used <= 0:
                    continue
                limit = limits.get(api) or 0
                if not limit:
                    logger.info(f"  {api + ' ' + label:18s}: {used:,} (한도 미설정)")
                    continue
                pct = (used / limit) * 100
                logger.info(f"  {api + ' ' + label:18s}: {used:,}/{limit:,} "
                            f"[{self._create_usage_bar(pct)}] {pct:5.1f}%")
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
