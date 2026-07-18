import json
import os
import sys
from typing import Dict, List

class ConfigError(Exception):
    """설정 관련 에러"""
    pass

class ArgusConfig:
    # ==========================================
    # [1] AI 모델 설정
    # ==========================================
    MODEL_PHASE_0 = "gemma-4-31b-it"  # 빠른 번역/요약 (Google AI Studio / Gemini API)
    MODEL_PHASE_1 = "openai/gpt-oss-120b"  # 심층 분석 주 모델 (Groq, 추론형)

    # 분석 3단(비상 폴백) — Groq 두 모델(TPD 각 200K)이 모두 소진/장애일 때만 사용.
    # 다른 공급자(Google AI Studio)라 Groq 장애 자체도 커버(이중화). flash-lite는
    # 번역(Gemma 31B)과 다른 모델이라 AI Studio 한도(모델별)를 나눠 쓰지 않는다.
    # 추론 깊이는 gpt-oss/qwen보다 낮지만 JSON 모드 지원으로 구조화 분석엔 충분.
    GEMINI_ANALYSIS_MODEL = "gemini-3.1-flash-lite"

    # Groq 심층분석 모델 캐스케이드 — 앞 모델의 일일 한도(TPD)가 소진되면 다음 모델로 자동 전환.
    # gpt-oss-120b와 qwen3.6은 TPD 200K/일이 '각각' 잡혀 실질 일일 예산 400K.
    #
    # ⚠️ compound/compound-mini는 제외한다: agentic 시스템이라 내부적으로 기반 모델
    # (gpt-oss-120b 등)을 호출하며, 토큰이 '기반 모델의 TPD'로 계상된다(429 로그로 확인:
    # compound 요청이 openai/gpt-oss-120b TPD 200K 한도에 걸림). 즉 예산이 합산되지 않고
    # 오히려 웹검색 컨텍스트만큼 같은 예산을 더 빨리 소모 + 다단계 실행으로 지연 + 비정형
    # 출력으로 파싱 재시도까지 유발 → 캐스케이드에 넣을 이유가 없다.
    GROQ_MODELS = [
        "openai/gpt-oss-120b",
        "qwen/qwen3.6-27b",
    ]

    # 모델별 일일 소진 기준. rpd=요청 수/일, tpd=토큰 수/일. None=해당 기준 무제한.
    GROQ_MODEL_LIMITS = {
        "openai/gpt-oss-120b": {"rpd": None, "tpd": 200_000},
        "qwen/qwen3.6-27b":    {"rpd": None, "tpd": 200_000},
    }

    # 심층 분석 공통 파라미터 (temp/top_p/max는 모델 공통). TPM이 250K로 상향되어 8K 제약이
    # 사라졌으므로 출력 상한을 넉넉히(4096) 둔다. reasoning은 모델별로 GROQ_MODEL_REASONING에서 지정.
    GROQ_ANALYSIS_PARAMS = {
        "temperature": 0.3,  # 일관된 출력 (hallucination 감소)
        "top_p": 0.9,
        "max_completion_tokens": 4096,
    }

    # 모델별 reasoning 파라미터 — 모델마다 지원값이 다르다. 값이 없으면(빈 dict) API 호출에서 생략.
    #   gpt-oss-120b: "low"(최소 추론) / qwen3.6: "none"(비추론). reasoning_format="parsed"로 JSON 보호.
    GROQ_MODEL_REASONING = {
        "openai/gpt-oss-120b": {"reasoning_effort": "low", "reasoning_format": "parsed"},
        "qwen/qwen3.6-27b": {"reasoning_effort": "none", "reasoning_format": "parsed"},
    }


    # ==========================================
    # [2] 성능 최적화 설정
    # ==========================================
    PERFORMANCE = {
        # TPM이 250K로 상향되어 병렬 워커의 8K TPM 429 폭주 위험이 사라짐 → 병렬 복원.
        # (Groq RPM 30 + 고위험당 분석 1회라 병렬로도 RPM 여유. 저위험 fetch 병렬화로 처리량↑.)
        "max_workers": 4,
        "rule_check_interval_days": 7,  # 공식 룰 재확인 주기
        # 실행당 처리 상한. 번역이 배치(translation_batch_size건/호출)라 250건이어도
        # Gemma 호출은 ~25회(=100초)뿐 — 30분 타임아웃 내 완주하며 백로그(수백~수천)를
        # 신속 해소한다(일 처리능력 250×24=6,000건 » 유입). RPD도 25×24=600콜/일로 여유.
        # (타임아웃으로 killed 되어도 워터마크 미저장 → 다음 실행 재수집, 누락 0.)
        "max_cves_per_run": 250,
        "translation_batch_size": 10,  # 일괄 번역: Gemma 호출당 CVE 수
        "max_rule_recheck": 10,  # 공식 룰 재확인 배치 크기
        # 에스컬레이션 재평가 스윕 — 레코드(cvelistV5) 미변경이라 재수집 큐에 안 올라오는
        # '현재 저위험' CVE의 외부 피드(KEV/EPSS/ExploitDB/Metasploit) 변화로 인한 고위험 승격
        # 누락을 메운다. 후보는 최근 N일·최신순 limit건, 실제 승격분만 풀 재처리(상한).
        "escalation_sweep_days": 30,      # 재평가 대상: 최근 며칠 내 CVE
        "escalation_candidate_limit": 300,  # 재평가 후보 상한 (EPSS 배치 = 50건/요청)
        "max_escalation_reprocess": 20    # 한 실행에서 풀 재처리할 승격 CVE 상한
    }
    
    # ==========================================
    # [3] 필수 환경 변수 목록
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