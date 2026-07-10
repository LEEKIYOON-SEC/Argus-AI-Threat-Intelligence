import json
import os
import sys
from typing import Dict, List, Optional

class ConfigError(Exception):
    """설정 관련 에러"""
    pass

class ArgusConfig:
    # ==========================================
    # [1] AI 모델 설정
    # ==========================================
    MODEL_PHASE_0 = "gemma-4-31b-it"  # 빠른 번역/요약 (Google AI Studio / Gemini API)
    MODEL_PHASE_1 = "qwen/qwen3.6-27b"  # 심층 분석 + 룰 생성 (Groq, 사고형 모델)

    # Qwen3.6은 사고형(thinking) 모델 — reasoning_effort는 "default"(thinking) / "none"(non-thinking)만 지원.
    # reasoning_format="parsed": 사고 과정을 응답의 reasoning 필드로 분리해 content엔 최종 답변만 남김
    # (JSON/룰 코드 파싱이 <think> 태그로 깨지지 않도록).
    # temperature/top_p는 Qwen 공식 권장값 — 사고 모드에서 너무 낮은 temp는 반복(degeneration) 유발.

    # [분석용] Groq 파라미터 - 복잡한 CVE 분석 (사고 모드)
    GROQ_ANALYSIS_PARAMS = {
        "temperature": 0.6,  # Qwen 사고 모드 권장 (코딩/정밀 작업)
        "top_p": 0.95,
        "max_completion_tokens": 8192,  # 사고 토큰 + 긴 분석
        "reasoning_effort": "default",  # 심층 분석은 항상 thinking
        "reasoning_format": "parsed"
    }

    # [룰 생성용] Groq 파라미터 - 정확한 코드 생성 (사고 모드)
    # 우선 thinking으로 룰 품질 극대화. TPD(일간 토큰) 부족 시 "none"으로 전환 가능.
    GROQ_RULE_PARAMS = {
        "temperature": 0.6,  # Qwen 사고 모드 권장
        "top_p": 0.95,
        "max_completion_tokens": 4096,  # 사고 토큰 + 룰 출력 여유 (기존 2048 → 4096)
        "reasoning_effort": "default",  # 룰 생성도 thinking (사용자 선택)
        "reasoning_format": "parsed"
    }
    
    # ==========================================
    # [2] AI 룰 생성 게이트
    # ==========================================
    RULE_GENERATION = {
        "epss_threshold": 0.2,  # EPSS >= 0.2이면 AI 룰 생성
        "require_exploitation_evidence": True,  # False = 기존 동작 (kill switch)
    }

    # ==========================================
    # [3] 성능 최적화 설정
    # ==========================================
    PERFORMANCE = {
        "max_workers": 3,  # 병렬 처리 워커 수 (너무 많으면 API 한도 초과)
        "batch_size": 10,  # 배치 처리 크기
        "cve_fetch_hours": 2,  # 최근 N시간 내 CVE 수집
        "rule_check_interval_days": 7,  # 공식 룰 재확인 주기
        "max_cves_per_run": 50,  # 한 실행당 최대 처리 CVE 수 (할당량 보호)
        "max_rule_recheck": 10,  # 공식 룰 재확인 배치 크기 (2h × 10건 = 하루 120건)
        "bulk_commit_threshold": 100  # 벌크 커밋 판단 기준 (파일 수)
    }
    
    # ==========================================
    # [4] 필수 환경 변수 목록
    # ==========================================
    REQUIRED_ENV_VARS = [
        "GH_TOKEN",
        "SUPABASE_URL",
        "SUPABASE_KEY",
        "SLACK_WEBHOOK_URL",
        "GROQ_API_KEY",
        "GEMINI_API_KEY"
    ]
    
    # 선택적 환경 변수
    OPTIONAL_ENV_VARS = [
        "NVD_API_KEY",       # NVD API (CVSS/CWE 보충)
        "VULNCHECK_API_KEY"  # VulnCheck KEV (확장 KEV 목록)
    ]
    
    def __init__(self):
        """초기화 시 자동으로 검증 수행"""
        self.target_assets = self._load_assets()
        self._validate_environment()
    
    def _load_assets(self) -> List[Dict[str, str]]:
        """
        감시 대상 자산 로드
        
        assets.json 파일에서 벤더/제품 정보를 읽음.
        파일이 없거나 잘못된 경우 기본값(전체 감시)을 사용.
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
        
        시스템이 실행되기 전에 필수 API 키들이 모두 설정되어 있는지 확인.
        하나라도 없으면 명확한 에러 메시지와 함께 즉시 중단.
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
        """시스템 헬스체크"""
        health = {
            "environment": True,
            "assets_loaded": bool(self.target_assets)
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

try:
    config = ArgusConfig()
except ConfigError as e:
    print(f"\n{e}\n")
    sys.exit(1)