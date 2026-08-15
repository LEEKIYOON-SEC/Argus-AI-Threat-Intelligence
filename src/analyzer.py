import os
import re
import json
import time
from google import genai
from google.genai import types as genai_types
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import Dict, Optional
from logger import logger
from config import config
from rate_limiter import rate_limit_manager, gemini_error_kind, gemini_backoff

class AnalyzerError(Exception):
    """분석 관련 에러"""
    pass

class Analyzer:
    def __init__(self):
        # HTTP 타임아웃 120초 — 행 방지 (실패는 정형 폴백이 흡수).
        gemini_key = os.environ.get("GEMINI_API_KEY")
        if not gemini_key:
            raise AnalyzerError("GEMINI_API_KEY not found")
        try:
            self.gemini_client = genai.Client(
                api_key=gemini_key,
                http_options=genai_types.HttpOptions(timeout=120_000),
            )
        except Exception:
            self.gemini_client = genai.Client(api_key=gemini_key)
        logger.info(f"Analyzer initialized ({config.GEMINI_ANALYSIS_MODEL} "
                    f"→ {config.GEMINI_ANALYSIS_FALLBACK_MODEL} → 정형 폴백)")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=30)
    )
    def analyze_cve(self, cve_data: Dict) -> Dict:
        """CVE 심층 분석. 3.5 → 3.1 → 정형 폴백.

        두 모델은 한도가 따로 잡히므로(각 RPD 500) 앞이 소진돼도 뒤가 살아 있다.
        둘 다 불가하면 정형 폴백으로 내려간다 — 리포트는 나가되 분석란이 안내문이
        되고, 워터마크가 붙잡지 않으므로 그 CVE는 이 실행에서 마무리된다."""
        logger.info(f"Analyzing {cve_data['id']} with AI...")
        prompt = self._build_analysis_prompt(cve_data)

        for model, limiter_key in (
            (config.GEMINI_ANALYSIS_MODEL, "gemini_analysis"),
            (config.GEMINI_ANALYSIS_FALLBACK_MODEL, "gemini_analysis_fb"),
        ):
            result = self._analyze_with_gemini(cve_data, prompt, model, limiter_key)
            if result is not None:
                return result
            logger.warning(f"{cve_data['id']}: {model} 분석 불가 → 다음 단계")

        return self._fallback_analysis(cve_data)

    # 한 모델에서의 일시 오류 재시도 횟수. 무한정 붙들면 다음 단계가 늦어지므로 짧게.
    _GEMINI_ATTEMPTS = 3

    def _analyze_with_gemini(self, cve_data: Dict, prompt: str,
                             model: str, limiter_key: str) -> Optional[Dict]:
        """지정한 flash-lite 모델로 분석. 실패하면 None(호출부가 다음 단계로 넘긴다).

        JSON 모드로 구조화 출력을 강제해 비정형 출력에 의한 파싱 실패를 막는다.
        일시 오류(503·분당 한도)는 여기서 재시도한다 — 구글의 몇 초짜리 혼잡 때문에
        그 CVE만 다른 모델이 분석하면 리포트 품질이 들쭉날쭉해진다. 일일 한도 소진
        (rpd)은 기다려도 풀리지 않으므로 즉시 마킹하고 넘긴다.

        limiter_key가 모델마다 다른 이유: AI Studio 한도는 모델별로 따로 잡히므로
        3.5가 소진돼도 3.1은 멀쩡하다. 한 키를 공유하면 멀쩡한 쪽까지 잠긴다."""
        if not self.gemini_client or not model:
            return None
        if rate_limit_manager.is_rpd_exhausted(limiter_key):
            logger.warning(f"{cve_data['id']}: {model} 일일 한도 소진")
            return None

        params = config.ANALYSIS_PARAMS
        for attempt in range(1, self._GEMINI_ATTEMPTS + 1):
            try:
                if not rate_limit_manager.check_and_wait(limiter_key):
                    return None   # 위 is_rpd_exhausted와 별개로, 동시 실행 중 소진된 경우
                response = self.gemini_client.models.generate_content(
                    model=model,
                    contents=prompt,
                    config=genai_types.GenerateContentConfig(
                        temperature=params["temperature"],
                        top_p=params["top_p"],
                        max_output_tokens=params["max_output_tokens"],
                        # flash-lite는 JSON 모드 지원 → 비정형 출력으로 인한 파싱 실패 차단
                        response_mime_type="application/json",
                        # 보안 분석 내용이 안전필터에 오차단되지 않게 (번역 경로와 동일 설정)
                        safety_settings=[genai_types.SafetySetting(
                            category="HARM_CATEGORY_DANGEROUS_CONTENT",
                            threshold="BLOCK_NONE"
                        )]
                    ),
                )
                rate_limit_manager.record_call(limiter_key)

                result = self._extract_json((response.text or "").strip())
                if result is None or not self._validate_analysis_result(result):
                    # JSON 모드에서도 필수 키가 빠질 수 있다. 형식 문제는 재시도해도
                    # 같은 결과일 확률이 높아 다음 모델로 넘긴다.
                    logger.warning(f"{cve_data['id']}: {model} 파싱/검증 실패")
                    return None
                logger.info(f"{cve_data['id']}: Analysis complete (model={model})")
                return result

            except Exception as e:
                kind = gemini_error_kind(str(e))
                # 일간 quota 429 → 대기 무의미, 즉시 소진 마킹 (이후 CVE는 바로 다음 모델).
                # 분당 한도 429는 마킹하지 않는다 — 소진 상태는 DB로 실행 간에 유지되므로
                # 오판하면 그 모델이 최대 24시간 잠긴다.
                if kind == "rpd":
                    rate_limit_manager.mark_rpd_exhausted(limiter_key)
                    logger.warning(f"{cve_data['id']}: {model} 일일 한도 소진")
                    return None
                if kind in ("rate", "transient") and attempt < self._GEMINI_ATTEMPTS:
                    wait = gemini_backoff(kind, attempt, str(e))
                    logger.warning(f"{cve_data['id']}: {model} {kind} 오류"
                                   f"({attempt}/{self._GEMINI_ATTEMPTS}) → {wait:.0f}s 후 재시도")
                    time.sleep(wait)
                    continue
                logger.warning(f"{cve_data['id']}: {model} 분석 실패({kind}): {e}")
                return None
        return None

    def _extract_json(self, text: str) -> Optional[Dict]:
        # 1차 시도: 그대로 파싱
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # 2차 시도: 마크다운 코드 블록 제거 후 파싱
        cleaned = re.sub(r"```(?:json)?\s*\n?", "", text).strip()
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # 3차 시도: 텍스트에서 첫 번째 JSON 객체 추출
        match = re.search(r'\{[\s\S]*\}', text)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None
    
    def _build_analysis_prompt(self, cve_data: Dict) -> str:
        
        # 추가 위협 인텔리전스 (있으면)
        enriched_section = ""
        
        # NVD CPE
        if cve_data.get('nvd_cpe'):
            cpe_list = ", ".join(cve_data['nvd_cpe'][:3])
            enriched_section += f"\nNVD CPE: {cpe_list}"
        
        # PoC 존재 여부
        if cve_data.get('has_poc'):
            poc_urls = cve_data.get('poc_urls', [])
            enriched_section += f"\nPoC: 공개됨 ({cve_data.get('poc_count', 0)}건)"
            if poc_urls:
                enriched_section += f" - {poc_urls[0]}"
        
        # GitHub Advisory
        advisory = cve_data.get('github_advisory', {})
        if advisory.get('has_advisory') and advisory.get('packages'):
            pkgs = [f"{p['ecosystem']}/{p['name']}" for p in advisory['packages'][:3]]
            enriched_section += f"\nAffected Packages: {', '.join(pkgs)}"
        
        # VulnCheck KEV
        if cve_data.get('is_vulncheck_kev'):
            enriched_section += "\nVulnCheck KEV: 실제 악용 확인됨"
        
        if enriched_section:
            enriched_section = f"\n[Additional Threat Intelligence]{enriched_section}\n"
        
        return f"""
You are a Senior Security Analyst. Analyze the following CVE based STRICTLY on the provided data.

=== ANTI-HALLUCINATION RULES (CRITICAL - APPLY TO ALL SECTIONS) ===
1. Use ONLY information explicitly stated in the [Context] and [Additional Threat Intelligence] below.
2. If specific technical details (function names, version numbers, file paths, API names) are NOT in the provided data, DO NOT invent them.
3. When you make an inference based on CWE type or CVSS vector (not from the description), prefix it with "[추정]".
   - Example: "[추정] CWE-121 (Stack Buffer Overflow) 특성상 경계 검증 누락이 원인으로 보인다."
   - Do NOT write: "memcpy/strcpy 함수의 경계 검증 누락이 원인이다." (unless these function names appear in the description)
4. For mitigation: NEVER fabricate specific version numbers for patches. Instead say "제조사의 최신 보안 패치 적용" or reference the vendor advisory.
5. For attack scenario: Base it on the CVSS vector and CWE, but mark inferred steps with [추정].
===

[Context]
CVE-ID: {cve_data['id']}
Description: {cve_data['description']}
CWE: {', '.join(cve_data.get('cwe', ['Unknown']))}
CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
Affected Products: {json.dumps(cve_data.get('affected', []))}
References: {json.dumps(cve_data.get('references', [])[:3])}
{enriched_section}
[Analysis Tasks]

1. **Root Cause Analysis**
   - Identify the technical root cause based on the description and CWE
   - If the description only mentions a vulnerability class (e.g., "buffer overflow") without specific function/component details, state that and add "[추정]" before any inference
   - DO NOT fabricate specific function names (e.g., memcpy, strcpy, eval) unless they appear in the description

2. **Attack Scenario (Kill Chain)** — 핵심 산출물, 가장 상세하게 작성
   - Start with "MITRE ATT&CK 기반 공격 흐름:"
   - Describe a realistic attack flow using the MITRE ATT&CK framework
   - Include AT LEAST 3 stages, each with a specific technique ID (e.g., T1210, T1059, T1190, T1078) AND its official name
   - Base every stage on the CVSS vector (AV/AC/PR/UI) and CWE — the entry stage must be consistent with the Attack Vector
   - Mark any step inferred from CWE/vector (not from the description) with [추정]
   - Use newline (\n) between each stage in the JSON string value
   - Format EXACTLY as:
     MITRE ATT&CK 기반 공격 흐름:\n**초기 접근(Initial Access)** – 설명 (T코드: 기법명). [추정]\n**실행(Execution)** – 설명 (T코드: 기법명). [추정]\n**영향(Impact)** – 설명 (T코드: 기법명). [추정]

3. **Business Impact Assessment**
   - Focus on REAL-WORLD operational consequences, NOT a restatement of the CVSS vector
     (the vector metrics are already shown separately — do NOT list AV/AC/PR/UI/VC/VI/VA values here)
   - Describe concretely: what data could be exposed/altered, what service could go down, and the
     likely business/compliance impact (e.g., 고객 데이터 유출, 서비스 전면 중단, 규정 위반 가능성)
   - Ground it in the CVSS impact metrics and CWE, but express it as consequences, not metric names
   - Mark inferences with [추정]

4. **Mitigation Strategy**
   - Check the Affected Products data above for version ranges (e.g., "X 부터 Y 이전")
     * If "lessThan"/"이전" version exists → recommend updating to that version or higher (e.g., "Y 이상으로 업데이트")
     * If "patch_version" field exists → use it as the recommended minimum version
     * If only "단일 버전" or "모든 버전" with no upper bound → say "제조사의 최신 보안 패치 적용" (DO NOT invent a version number)
   - NEVER fabricate version numbers that are not present in the provided data
   - Suggest general workarounds based on the vulnerability class
   - Reference the vendor advisory URL if available in References

[Language & Terminology]
- Translate ALL output values into Korean (한국어)
- KEEP technical terms in English or Korean transliteration:
  - Good: "Buffer Overflow", "버퍼 오버플로우", "SQL Injection", "SQL 인젝션"
  - Bad: "완충 범람", "SQL 주입"
- JSON keys must remain in English

[Output Format]
Return ONLY a valid JSON object:
{{
  "root_cause": "한국어 설명 (추론 시 [추정] 표기)",
  "scenario": "한국어 공격 시나리오 (MITRE 기법 ID 3개 이상, 추론 시 [추정] 표기)",
  "impact": "한국어 영향도 평가",
  "mitigation": ["단계별", "대응", "방안"]
}}

Do NOT include markdown code fences or any text outside the JSON.
"""
    
    def _validate_analysis_result(self, result: Dict) -> bool:
        """AI 응답 검증"""
        required_keys = ['root_cause', 'scenario', 'impact', 'mitigation']

        for key in required_keys:
            if key not in result:
                logger.warning(f"Missing required key: {key}")
                return False

        if not isinstance(result['mitigation'], list):
            logger.warning("mitigation must be a list")
            return False

        return True
    
    def _fallback_analysis(self, cve_data: Dict) -> Dict:
        """폴백 분석 결과"""
        logger.warning(f"{cve_data['id']}: Using fallback analysis (AI failed)")
        
        return {
            "root_cause": f"자동 분석 실패 - {cve_data.get('description', 'No description')[:100]}",
            "scenario": "AI 분석을 수행할 수 없습니다. 제조사의 권고사항을 참조하세요.",
            "impact": "정보 부족으로 영향도를 평가할 수 없습니다.",
            "mitigation": [
                "제조사 보안 권고문 확인",
                "영향받는 버전 확인 후 패치 적용",
                "취약 구간 네트워크 접근 제한"
            ]
        }