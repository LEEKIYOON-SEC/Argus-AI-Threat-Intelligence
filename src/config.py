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
    # AI는 Google AI Studio 하나만 쓴다. 모델은 각 역할마다 2단이고, 둘 다 불가하면
    # 정형 폴백(_fallback_analysis / 영문 원문)으로 내려가 파이프라인은 계속 돈다.
    #
    #   분석  gemini-3.5-flash-lite  →  gemini-3.1-flash-lite  →  정형 폴백
    #   번역  gemma-4-31b-it         →  gemma-4-26b-a4b-it     →  영문 원문
    #
    # 공급자를 하나로 좁힌 대신 역할마다 모델을 2단으로 둔다. 이유는 도달률이다 —
    # 분석은 Critical만이라 하루 6~30건인데 RPD가 500이라 1단이 소진될 일이 거의 없고,
    # 소진되더라도 같은 역할의 다른 모델이 이어받는다(한도는 모델별로 따로 잡힌다).
    # 최종 안전망은 정형 폴백이다. 공급자가 통째로 죽어도 리포트는 나가고 워터마크가
    # 붙잡아 다음 실행에서 재처리된다 — 유실이 아니라 지연이다. 대신 그동안 분석란은
    # 안내문으로 나간다(불변 원칙 5: 단일 공급자 + 역할별 2단 + 정형 폴백).

    # 번역 — Gemma. 한도는 모델마다 별도로 잡힌다(31B 소진이 26B에 영향 없음).
    MODEL_PHASE_0 = "gemma-4-31b-it"
    MODEL_PHASE_0_FALLBACK = "gemma-4-26b-a4b-it"

    # 심층 분석 — flash-lite. 3.5가 후속 모델이고 한도는 3.1과 동일(RPM 15 / TPM 250K /
    # RPD 500)이라 교체해도 예산 구조가 바뀌지 않는다.
    # 번역(Gemma)과 다른 모델이라 AI Studio 한도를 나눠 쓰지 않는다.
    MODEL_PHASE_1 = "gemini-3.5-flash-lite"
    GEMINI_ANALYSIS_MODEL = "gemini-3.5-flash-lite"
    GEMINI_ANALYSIS_FALLBACK_MODEL = "gemini-3.1-flash-lite"

    # 심층 분석 공통 파라미터. JSON 모드로 구조화 출력이 보장돼 파싱 실패로 티어가
    # 갈리는 일이 없다 — 품질의 평균보다 편차가 중요하다.
    ANALYSIS_PARAMS = {
        "temperature": 0.3,  # 일관된 출력 (hallucination 감소)
        "top_p": 0.9,
        "max_output_tokens": 4096,
    }

    # ==========================================
    # [2] 성능 최적화 설정
    # ==========================================
    PERFORMANCE = {
        # 분석 TPM 250K에 고위험당 분석 1회라 병렬로도 분당 한도에 여유가 있다.
        # 저위험 fetch 병렬화로 처리량을 올린다.
        "max_workers": 4,
        "rule_check_interval_days": 7,  # 공식 룰 재확인 주기
        # 실행당 처리 상한. 자산 기준 티어링으로 비자산 저위험(유입의 대부분)은 번역 없이
        # 마커 저장만 하므로 건당 비용이 급감 — 400건이어도 시간 예산 내 완주.
        # 일 처리능력 400×24=9,600건 » 유입 → 백로그 신속 해소. (소프트 데드라인이 초과 보호.)
        "max_cves_per_run": 400,
        # 일괄 번역 배치 크기. gemma-4는 배치가 크면 JSON 배열을 자주 깨뜨려(잘림·형식이탈)
        # 파싱 실패 → 개별 폴백이 잦아진다. 6건이면 형식 안정성↑, 실패 시 개별 폴백이 흡수.
        "translation_batch_size": 6,
        # 번역 청크 동시 호출 수. 병목은 콜 1건의 생성 지연(~55초/청크)이지 한도가 아님 —
        # 직렬이면 RPM 15 중 ~1.1만 쓰면서 66청크에 60분. 동시 4콜 = RPM ~4.4·TPM ~12K로
        # 여전히 한도 절반 이하, 벽시계 시간은 ~1/4. (RPD는 콜 수 불변이라 영향 없음)
        "translation_concurrency": 4,
        # 소프트 데드라인 — GitHub Actions timeout(45분)에 killed 되기 전에 스스로 마무리한다.
        # 초과 시: 잔여 CVE를 failed로 남기고(워터마크가 붙잡아 다음 실행 재처리) 워터마크
        # 저장·요약까지 정상 종료. killed 되면 워터마크를 못 써 다음 실행이 수집을 통째로
        # 반복하므로, '항상 깨끗하게 끝내고 전진'이 핵심. (잡 셋업/export/commit 여유 ~7분)
        "soft_deadline_minutes": 38,
        # Phase C(Issue·Slack·저장) 전용 시간 예약 — 번역(Phase B)의 데드라인을 이만큼
        # 앞당긴다. 백로그로 번역 청크가 많을 때 번역이 전체 예산을 다 먹고 Phase C가
        # 0초로 시작→Critical 알림까지 통째로 취소되는 기아(starvation)를 방지.
        # (관측: 66청크×55초 » 예산 → 번역이 38분 데드라인 직전까지 점유, 알림 5/31건만 발송)
        "phase_c_reserve_minutes": 8,
        # 이월(백로그) 대기열 심각도 추정 표본 크기 — raw JSON(API 한도 미소모)로 CVSS만
        # 읽어 분포를 외삽해 로그로 남긴다(관측 전용, 0=끔). 80건 ≈ ±10%p 오차, 소요 ~10초.
        "deferred_severity_sample": 80,
        # 독약(poison-pill) 레코드 격리 — 매번 실패하는 CVE 1건이 워터마크를 영구 고정해
        # 조회 창까지 얼어붙는(신규 CVE 전면 미수집) 사고를 막는다. 연속 N회 실패 시 격리,
        # M시간 후 자동 해제·재시도 → 일시 장애가 연속으로 겹친 경우 스스로 회복.
        "max_consecutive_failures": 3,
        "quarantine_retry_hours": 24,
        # 번역 백필 — 시간 예산 초과로 영문 폴백된 채 굳어버린 추적 CVE를 매 실행 소량씩
        # 재번역해 대시보드 한글화율을 회복한다. pool=조회 후보 수, per_run=실제 번역 건수.
        # (0이면 비활성. 본 처리 후 여유 시간이 있을 때만 동작 — 파이프라인 침범 없음)
        "translation_backfill_pool": 200,
        "translation_backfill_per_run": 24,
        "max_rule_recheck": 10,  # 공식 룰 재확인 배치 크기
        # 에스컬레이션 재평가 스윕 — 레코드(cvelistV5) 미변경이라 재수집 큐에 안 올라오는
        # '현재 저위험' CVE의 외부 피드(KEV/EPSS/ExploitDB/Metasploit) 변화로 인한 고위험 승격
        # 누락을 메운다. 후보는 최근 N일·최신순 limit건, 실제 승격분만 풀 재처리(상한).
        "escalation_sweep_days": 30,      # 재평가 대상: 최근 며칠 내 CVE
        "escalation_candidate_limit": 300,  # 재평가 후보 상한 (EPSS 배치 = 50건/요청)
        "max_drift_candidates": 60,       # 신호 드리프트(KEV/EPSS) 1회 추가 상한. 나머지는
                                          # 다음 실행이 이어받는다(신호가 소스에 남아 있으므로)
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