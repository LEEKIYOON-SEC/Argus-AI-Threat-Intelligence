import os
import sys
from typing import Dict

class ConfigError(Exception):
    pass

class ArgusConfig:
    MODEL_PHASE_0 = "gemma-4-31b-it"
    MODEL_PHASE_0_FALLBACK = "gemma-4-26b-a4b-it"

    GEMINI_ANALYSIS_MODEL = "gemini-3.5-flash-lite"
    GEMINI_ANALYSIS_FALLBACK_MODEL = "gemini-3.1-flash-lite"

    ANALYSIS_PARAMS = {
        "temperature": 0.3,
        "top_p": 0.9,
        "max_output_tokens": 4096,
    }

    PERFORMANCE = {
        "max_workers": 4,

        "fast_max_changes": 1500,
        "fast_deadline_minutes": 5,
        "snapshot_cap": 80,

        "bulk_deadline_minutes": 38,
        "translation_batch_size": 6,
        "translation_concurrency": 4,
        "translation_backfill_pool": 200,

        # 번역은 이제 '회차당 N건'이 아니라 **시간 예산과 API 한도**로 멈춘다.
        # 예전에는 24건 고정이었는데, 실측으로 bulk-lane 은 하루 5.0회밖에 안 돈다
        # (cron 은 시간당 1회지만 GitHub 이 그만큼 안 띄운다 — 간격 중앙값 4.8시간,
        # 최대 13.3시간, 설계 대비 21%). 24 x 5 = 120건/일 이라 미번역 2,340건을
        # 지우는 데 20일이 걸렸다. 정작 bulk-lane 은 38분 예산 중 23초만 쓰고 끝났다.
        # 그래서 남은 시간과 남은 RPD/TPD 가 허락하는 만큼 돌린다.
        "translation_minutes": 18,        # 이 단계에 줄 시간 (뒤 단계 몫을 남긴다)
        "translation_max_per_run": 1500,  # 안전 상한 — 한 회차가 끝없이 길어지지 않게
        "translation_daily_reserve": 0.15,  # 하루 한도의 15%는 다른 용도로 남긴다

        "max_rule_recheck": 10,

        "max_consecutive_failures": 3,
        "quarantine_retry_hours": 24,
    }

    REQUIRED_ENV_VARS = [
        "GH_TOKEN",
        "SUPABASE_URL",
        "SUPABASE_KEY",
        "SLACK_WEBHOOK_URL",
        "GEMINI_API_KEY"
    ]
    
    def __init__(self):
        self._validate_environment()
    
    def _validate_environment(self):
        missing = []
        
        for var in self.REQUIRED_ENV_VARS:
            value = os.environ.get(var)
            if not value or value.strip() == "":
                missing.append(var)
        
        if missing:
            error_msg = f"""
❌ 필수 환경 변수가 설정되지 않았습니다:
{chr(10).join(f'  - {var}' for var in missing)}

GitHub Actions Secrets에 다음 변수들을 추가해주세요.
"""
            raise ConfigError(error_msg)
    
    def health_check(self) -> Dict[str, bool]:
        health = {"environment": True}
        
        try:
            self._validate_environment()
        except ConfigError:
            health["environment"] = False
        
        return health
    
try:
    config = ArgusConfig()
except ConfigError as e:
    print(f"\n{e}\n")
    sys.exit(1)
