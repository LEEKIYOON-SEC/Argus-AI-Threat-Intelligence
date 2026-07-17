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
    MODEL_PHASE_1_FALLBACK = "openai/gpt-oss-120b"  # Qwen TPD 소진 시 폴백 (Groq, 별도 TPD 버킷)

    # Groq 무료 TPD는 모델별로 따로 잡힌다(각 200K/일). 따라서 주 모델(Qwen) 소진 시
    # 폴백 모델(GPT-OSS-120B)로 넘기면 하루 예산이 사실상 2배가 된다. 우선순위 순서.
    GROQ_MODELS = [MODEL_PHASE_1, MODEL_PHASE_1_FALLBACK]

    # Qwen3.6은 사고형(thinking) 모델 — reasoning_effort는 "default"(thinking) / "none"(non-thinking)만 지원.
    # ⚠️ 무료 티어 제약(TPM 8,000): Groq은 (입력 + max_completion_tokens)를 TPM에 선예약하므로
    # 단일 요청이 8K를 넘으면 무조건 실패한다. 따라서 무료 티어에선 non-thinking + 작은
    # max_completion_tokens가 필수. thinking(사고 토큰 수천)은 8K TPM에 물리적으로 불가.
    # 유료(Developer) 전환 시: reasoning_effort "default" + max_completion 상향으로 thinking 복원.
    # reasoning_format="parsed": content에 최종 답변만 남겨 JSON/룰 파싱이 깨지지 않도록(무해, 유지).

    # [분석용] Groq 파라미터 - non-thinking, 8K TPM 적합 (temp/top_p/max는 모델 공통)
    # AI 룰 생성 제거로 토큰 예산 확보 → 분석 출력 상향(시나리오/MITRE/벡터 충실).
    # 입력~1.5K + 4096 ≈ 5.6K < 8K TPM 안전.
    GROQ_ANALYSIS_PARAMS = {
        "temperature": 0.3,  # 일관된 출력 (hallucination 감소)
        "top_p": 0.9,
        "max_completion_tokens": 4096,  # 분석 집중(룰 예산 회수분)
        "reasoning_effort": "none",  # 무료 티어: non-thinking 필수
        "reasoning_format": "parsed"
    }

    # [룰 생성용] Groq 파라미터 - non-thinking, 정확한 코드 생성
    GROQ_RULE_PARAMS = {
        "temperature": 0.2,  # 코드는 창의성보다 정확성
        "top_p": 0.85,
        "max_completion_tokens": 2048,  # 입력~2K + 2048 ≈ 4K < 8K TPM
        "reasoning_effort": "none",  # 무료 티어: non-thinking 필수
        "reasoning_format": "parsed"
    }

    # 모델별 reasoning 파라미터 오버라이드 — 모델마다 지원하는 값이 다르므로 분리.
    # GPT-OSS-120B는 "none"을 지원하지 않아 "low"(최소 추론)로 둔다. temp/top_p/max_completion은
    # 위 ANALYSIS/RULE_PARAMS를 공통 사용하되, reasoning_effort/format만 여기서 덮어쓴다.
    # 값이 없으면 해당 파라미터를 API 호출에서 생략한다.
    GROQ_MODEL_REASONING = {
        "qwen/qwen3.6-27b": {"reasoning_effort": "none", "reasoning_format": "parsed"},
        "openai/gpt-oss-120b": {"reasoning_effort": "low", "reasoning_format": "parsed"},
    }
    

    # ==========================================
    # [3] 성능 최적화 설정
    # ==========================================
    PERFORMANCE = {
        # 무료 티어(8K TPM): 병렬 워커가 분당 토큰을 동시 소진해 429 폭주 → 단일 워커.
        # 유료(Developer) 전환 시 3~5로 복원.
        "max_workers": 1,
        "rule_check_interval_days": 7,  # 공식 룰 재확인 주기
        # 실행당 처리 상한. 대부분 CVE는 저위험 = 번역+DB저장(값싼 경로)이고,
        # 무거운 Groq 룰 생성은 고위험만(is_high_risk 게이트) 타므로 상한을 높여도 안전하다.
        # 15는 Groq TPM 보호용으로 과하게 낮았음 → 유입(~150건/일) 대비 백로그 누적.
        # 50 × cron(~8회/일) = 400건/일 > 유입 → 백로그 해소. 30분 타임아웃 내 완주.
        # (타임아웃으로 killed 되어도 워터마크 미저장 → 다음 실행 재수집, 누락 0.)
        "max_cves_per_run": 50,
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