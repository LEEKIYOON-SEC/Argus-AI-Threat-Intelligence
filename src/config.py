import json
import os
import sys
from typing import Dict, List, Optional

class ConfigError(Exception):
    """설정 관련 에러"""
    pass

class ArgusConfig:
    """
    Argus 시스템 설정 관리 클래스
    
    기능:
    1. 환경 변수 검증 (필수 API 키 체크)
    2. 설정 파일 로드 및 유효성 검사
    3. 시스템 헬스체크
    
    이렇게 클래스로 만든 이유:
    - 설정을 한 곳에서 관리하면 나중에 수정하기 쉽습니다
    - 검증 로직을 체계적으로 구성할 수 있습니다
    - 싱글톤 패턴으로 전역 접근 가능합니다
    """
    
    # ==========================================
    # [1] AI 모델 설정
    # ==========================================
    MODEL_PHASE_0 = "gemma-3-27b-it"  # 빠른 번역/요약
    MODEL_PHASE_1 = "openai/gpt-oss-120b"  # 심층 분석
    
    # [분석용] Groq 파라미터 - 복잡한 CVE 분석
    GROQ_ANALYSIS_PARAMS = {
        "temperature": 0.3,  # 낮을수록 일관된 출력 (hallucination 감소)
        "top_p": 0.9,
        "max_completion_tokens": 8192,  # 긴 분석을 위해 증가
        "reasoning_effort": "high",
        "response_format": {"type": "json_object"}
    }
    
    # [룰 생성용] Groq 파라미터 - 정확한 코드 생성
    GROQ_RULE_PARAMS = {
        "temperature": 0.2,  # 더 엄격하게 (코드는 창의성보다 정확성)
        "top_p": 0.85,
        "max_completion_tokens": 2048,
        "reasoning_effort": "high"
    }
    
    # ==========================================
    # [2] Docker 설정 (현재 비활성화)
    # ==========================================
    DOCKER_CONFIG = {
        "enabled": False,  # GitHub Actions에서 Docker 이미지 없으므로 비활성화
        "snort_image": "snort/snort3",  # 향후 사용 시를 위한 설정
        "timeout": 20
    }
    
    # ==========================================
    # [3] API Rate Limit 설정
    # ==========================================
    RATE_LIMITS = {
        "github_api": {
            "calls_per_hour": 5000,  # GitHub API 기본 한도
            "delay_between_calls": 1  # 초 단위
        },
        "groq_api": {
            "calls_per_minute": 30,
            "delay_between_calls": 2
        },
        "epss_api": {
            "calls_per_minute": 60,
            "delay_between_calls": 1
        }
    }
    
    # ==========================================
    # [4] 성능 최적화 설정
    # ==========================================
    PERFORMANCE = {
        "max_workers": 3,  # 병렬 처리 워커 수 (너무 많으면 API 한도 초과)
        "batch_size": 10,  # 배치 처리 크기
        "cve_fetch_hours": 48,  # 최근 N시간 내 CVE 수집
        "rule_check_interval_days": 7  # 공식 룰 재확인 주기
    }
    
    # ==========================================
    # [5] 필수 환경 변수 목록
    # ==========================================
    REQUIRED_ENV_VARS = [
        "GH_TOKEN",
        "SUPABASE_URL",
        "SUPABASE_KEY",
        "SLACK_WEBHOOK_URL",
        "GROQ_API_KEY",
        "GEMINI_API_KEY"
    ]
    
    def __init__(self):
        """초기화 시 자동으로 검증 수행"""
        self.target_assets = self._load_assets()
        self._validate_environment()
    
    def _load_assets(self) -> List[Dict[str, str]]:
        """
        감시 대상 자산 로드
        
        assets.json 파일에서 벤더/제품 정보를 읽어옵니다.
        파일이 없거나 잘못된 경우 기본값(전체 감시)을 사용합니다.
        """
        file_path = "assets.json"
        default_rules = [{"vendor": "*", "product": "*"}]
        
        if not os.path.exists(file_path):
            return default_rules
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                rules = data.get("active_rules", default_rules)
                
                # 유효성 검사
                if not isinstance(rules, list):
                    raise ConfigError("active_rules must be a list")
                
                for rule in rules:
                    if not isinstance(rule, dict):
                        raise ConfigError("Each rule must be a dict")
                    if "vendor" not in rule or "product" not in rule:
                        raise ConfigError("Rules must have 'vendor' and 'product' keys")
                
                return rules
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in assets.json: {e}")
        except Exception as e:
            raise ConfigError(f"Failed to load assets.json: {e}")
    
    def _validate_environment(self):
        """
        환경 변수 검증
        
        시스템이 실행되기 전에 필수 API 키들이 모두 설정되어 있는지 확인합니다.
        하나라도 없으면 명확한 에러 메시지와 함께 즉시 중단합니다.
        
        이렇게 하는 이유:
        - 실행 중간에 실패하는 것보다 시작 전에 체크하는 게 낫습니다
        - 어떤 키가 빠졌는지 명확히 알려줍니다
        """
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
        """
        시스템 헬스체크
        
        Docker는 사용하지 않으므로 체크에서 제외합니다.
        필수 컴포넌트만 체크합니다.
        
        Returns:
            각 컴포넌트의 상태 (True: 정상, False: 문제 있음)
        """
        health = {
            "environment": True,
            "assets_loaded": bool(self.target_assets)
            # docker_available 제거 - Docker를 사용하지 않으므로
        }
        
        # 환경 변수 재확인
        try:
            self._validate_environment()
        except ConfigError:
            health["environment"] = False
        
        return health
    
    def get_target_assets(self) -> List[Dict[str, str]]:
        """감시 대상 자산 목록 반환"""
        return self.target_assets

# 전역 설정 인스턴스 (싱글톤)
try:
    config = ArgusConfig()
except ConfigError as e:
    print(f"\n{e}\n")
    sys.exit(1)
