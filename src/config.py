import os
import sys
from typing import Dict

class ConfigError(Exception):
    pass

class ArgusConfig:
    MODEL_PHASE_0 = "gemma-4-31b-it"
    MODEL_PHASE_0_FALLBACK = "gemma-4-26b-a4b-it"

    MODEL_PHASE_1 = "gemini-3.5-flash-lite"
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
        "translation_backfill_per_run": 24,
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
    
    OPTIONAL_ENV_VARS = [
        "NVD_API_KEY",
        "VULNCHECK_API_KEY"
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
