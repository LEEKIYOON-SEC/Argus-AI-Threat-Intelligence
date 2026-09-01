import os
import sys
from typing import Dict

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
    # [2] 실행 예산
    # ==========================================
    # 구조가 '전량 처리 후 일부 알림'에서 '고위험만 빠르게 알림'으로 바뀌면서 예산의
    # 성격도 달라졌다. 예전 값들(max_cves_per_run=400, 이월 대기열, 소프트 데드라인 38분)은
    # 하루 수천 건을 번역까지 해서 밀어 넣던 시절의 것이다. 지금은 fast-lane이 알림만
    # 책임지고 무거운 일은 bulk-lane으로 내려갔다.
    PERFORMANCE = {
        "max_workers": 4,

        # ── fast-lane (5분 주기) ──
        # 한 회차에서 판정할 변경 CVE 상한.
        #
        # 300이었다가 1,500으로 올렸다. 근거는 실측이다(2026-09-01, 6시간 창 607건).
        #
        #   레코드 확보   일별 ZIP 하나로 591/607건 · 2.5초   (개별 fetch는 14건/s)
        #   파싱 + 판정   590건 · 0.02초 = 23,886건/s        (메모리 조회뿐)
        #   DB 조회       590건 중 판정 결과가 T3이라 DB에 있을 리 없는 게 534건(90.5%)
        #
        # 즉 300이라는 상한이 막고 있던 비용은 레코드도 판정도 아니고 **건별 DB 왕복**
        # 하나였다. 그건 일괄 조회(RowCache)로 없앴다 — 600건이 왕복 600회에서 3회가 된다.
        # 실제 비용은 이제 저장(upsert)뿐이고, 그건 T0~T2 몫이라 600건 중 56건이다.
        #
        # 왜 굳이 올려야 했나: GitHub Actions의 스케줄 실행은 5분 주기를 지켜 주지 않는다.
        # 부하가 몰리면 10~30분씩 밀리고, 그동안 변경분이 쌓인다. 상한이 낮으면 밀린 만큼
        # 따라잡지 못해 지연이 누적된다 — 알림이 '빠른' 것이 목적인데 그 목적을 잃는다.
        "fast_max_changes": 1500,
        # fast-lane 소프트 데드라인. Actions 타임아웃(8분)에 killed 되면 워터마크를 못 써
        # 다음 회차가 같은 구간을 반복한다. 그 전에 스스로 마무리한다.
        "fast_deadline_minutes": 5,
        # 스냅샷 대조에서 한 소스가 한 회차에 밀어 넣을 수 있는 신규 CVE 상한.
        # EPSS 모델 갱신처럼 수천 건이 한꺼번에 임계를 넘는 날을 위한 안전판.
        "snapshot_cap": 80,

        # ── bulk-lane (시간별) ──
        "bulk_deadline_minutes": 38,
        # 번역 대상은 이제 '대시보드에 실리는 것 전부'(T0~T2)다. 저위험 전량 추적을
        # 그만두면서 하루 수천 건이 수십~수백 건으로 줄어, 전량 한글화가 예산 안에 들어온다.
        "translation_batch_size": 6,
        "translation_concurrency": 4,
        "translation_backfill_pool": 200,
        "translation_backfill_per_run": 24,
        "max_rule_recheck": 10,

        # ── 공통 ──
        # 독약(poison-pill) 격리 — 매번 실패하는 CVE 1건이 워터마크를 영구 고정해
        # 조회 창까지 얼어붙는 사고를 막는다. 연속 N회 실패 시 격리, M시간 후 자동 해제.
        "max_consecutive_failures": 3,
        "quarantine_retry_hours": 24,
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
        self._validate_environment()
    
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
        health = {"environment": True}
        
        # 환경 변수 재확인
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