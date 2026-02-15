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
    min_interval: float = 0.0   # 호출 간 최소 간격 (초)
    last_call_at: float = 0.0   # 마지막 호출 시각 (time.time)
    
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
    
    def should_wait(self) -> bool:
        return self.usage_percent >= 80

class RateLimitManager:
    """
    API Rate Limit 통합 관리자 (v3.0)
    
    v3.0 변경사항:
    - ✅ threading.Lock으로 thread safety 확보
      → 병렬 워커(ThreadPoolExecutor)에서 동시 호출 방지
    - ✅ github_search 전용 rate limit 추가 (10회/분)
    - ✅ gemini limit을 25로 하향 (Free Tier 30 RPM 대응)
    - ✅ min_interval(최소 호출 간격) 지원
    - ✅ handle_429() 메서드 추가 (Retry-After 파싱)
    - ✅ parse_retry_after() - Gemini 429 메시지에서 대기 시간 추출
    """
    
    def __init__(self):
        """
        ⚠️ 중요 Rate Limit 설정:
        - github: 5000회/시간 (일반 API)
        - github_search: 10회/분 (Search API, 매우 엄격!)
        - gemini: Free Tier 30 RPM → 보수적으로 25
        - groq: 30회/분
        """
        self.limits: Dict[str, RateLimitInfo] = {
            "github": RateLimitInfo(
                limit=5000,
                window_seconds=3600,
                min_interval=0.5
            ),
            "github_search": RateLimitInfo(
                limit=8,               # 실제 10, 여유분 확보
                window_seconds=60,
                min_interval=7.0       # 60초/8회 ≈ 7.5초
            ),
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
            # ✅ Gemini Free Tier: 30 RPM, 15K TPM
            # 보수적으로 25회, 병렬 환경에서 안전하게 2.5초 간격
            "gemini": RateLimitInfo(
                limit=25,
                window_seconds=60,
                min_interval=2.5       # 60초/25회 = 2.4초, 넉넉히 2.5초
            ),
            "ruleset_download": RateLimitInfo(
                limit=20,
                window_seconds=3600,
                min_interval=2.0
            )
        }
        
        # ✅ Thread Safety Lock
        # ThreadPoolExecutor에서 3개 워커가 동시에 check_and_wait() 호출 시
        # Lock 없으면 3개 모두 "사용 가능"으로 판단 → 동시 호출 → 429 발생
        self._lock = threading.Lock()
        
        self.stats = {
            "total_calls": 0,
            "total_waits": 0,
            "total_wait_time": 0.0,
            "rate_limit_hits": 0
        }
        
        logger.info("Rate Limit Manager v3.0 초기화 완료 (Thread-Safe)")
    
    def check_and_wait(self, api_name: str) -> bool:
        """
        API 호출 전 반드시 호출. Lock으로 동시 접근 차단.
        
        작동 과정:
        1. Lock 획득 (다른 스레드 대기)
        2. 리셋 시간 확인 및 카운터 초기화
        3. 최소 호출 간격(min_interval) 대기
        4. 한도 소진 시 리셋까지 대기
        5. 80%+ 사용 시 속도 조절
        6. Lock 해제
        """
        if api_name not in self.limits:
            logger.warning(f"알 수 없는 API: {api_name}, Rate Limit 적용 안 됨")
            return True
        
        with self._lock:
            info = self.limits[api_name]
            now = datetime.now()
            
            # Step 1: 리셋 시간 확인 및 초기화
            if now >= info.reset_at:
                old_used = info.used
                info.used = 0
                info.reset_at = now + timedelta(seconds=info.window_seconds)
                if old_used > 0:
                    logger.debug(f"{api_name} Rate Limit 리셋 (이전 사용: {old_used}/{info.limit})")
            
            # Step 2: 최소 호출 간격 대기
            if info.min_interval > 0 and info.last_call_at > 0:
                elapsed = time.time() - info.last_call_at
                if elapsed < info.min_interval:
                    wait_time = info.min_interval - elapsed
                    logger.debug(f"{api_name} 최소 간격 대기: {wait_time:.1f}초")
                    time.sleep(wait_time)
                    self.stats["total_wait_time"] += wait_time
            
            # Step 3: 한도 소진 확인
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
            
            # Step 4: 사용률 기반 속도 조절
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
                logger.debug(
                    f"{api_name} 사용률: {usage:.1f}% "
                    f"({info.remaining}개 남음) - 속도 조절"
                )
                time.sleep(extra_wait)
                self.stats["total_wait_time"] += extra_wait
        
        return True
    
    def record_call(self, api_name: str):
        """API 호출 기록 (Thread-Safe)"""
        if api_name not in self.limits:
            return
        
        with self._lock:
            info = self.limits[api_name]
            info.used += 1
            info.last_call_at = time.time()
            self.stats["total_calls"] += 1
            
            logger.debug(
                f"{api_name} 호출 기록: {info.used}/{info.limit} "
                f"({info.usage_percent:.1f}%)"
            )
    
    def handle_429(self, api_name: str, retry_after: Optional[float] = None):
        """
        429 Too Many Requests 대응 (Thread-Safe)
        
        1. 카운터를 한도로 마킹 (소진 상태)
        2. Retry-After 만큼 대기
        3. 리셋
        """
        with self._lock:
            self.stats["rate_limit_hits"] += 1
            
            if api_name not in self.limits:
                wait_time = retry_after if retry_after else 60
                logger.warning(f"⚠️ {api_name} 429 수신, {wait_time:.0f}초 대기")
                time.sleep(wait_time)
                return
            
            info = self.limits[api_name]
            info.used = info.limit  # 한도 소진으로 마킹
            
            if retry_after:
                wait_time = retry_after + 2  # 안전 마진 2초
            else:
                wait_time = info.time_until_reset
                if wait_time <= 0:
                    wait_time = info.window_seconds
            
            logger.warning(
                f"⚠️ {api_name} 429 수신! "
                f"{wait_time:.0f}초 대기 후 재시도 "
                f"(누적 429: {self.stats['rate_limit_hits']}회)"
            )
        
        # Lock 밖에서 sleep (다른 스레드가 Lock을 기다리지 않도록)
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
        
        Gemini 429 메시지 예시:
        "Please retry in 58.684150486s."
        
        Returns:
            대기 시간(초) 또는 None
        """
        match = re.search(r'retry in (\d+\.?\d*)s', str(error_message), re.IGNORECASE)
        if match:
            return float(match.group(1))
        
        # Retry-After 헤더 스타일 (정수 초)
        match = re.search(r'Retry-After:\s*(\d+)', str(error_message))
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
                    "api": api_name,
                    "used": info.used,
                    "limit": info.limit,
                    "remaining": info.remaining,
                    "usage_percent": round(info.usage_percent, 1),
                    "reset_in": round(info.time_until_reset, 0)
                }
            
            return {
                "apis": {
                    name: {
                        "used": info.used,
                        "limit": info.limit,
                        "remaining": info.remaining,
                        "usage": f"{info.usage_percent:.1f}%"
                    }
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
        
        if percent >= 90:
            symbol = "█"
        elif percent >= 70:
            symbol = "▓"
        else:
            symbol = "░"
        
        return symbol * filled + "░" * empty

# 전역 인스턴스 (모든 모듈에서 import하여 사용)
rate_limit_manager = RateLimitManager()