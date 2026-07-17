import os
import re
import json
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import Dict, Optional
from logger import logger
from config import config
from rate_limiter import rate_limit_manager

class AnalyzerError(Exception):
    """분석 관련 에러"""
    pass

class Analyzer:
    def __init__(self):
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise AnalyzerError("GROQ_API_KEY not found")
        
        self.client = Groq(api_key=api_key)
        # 사용 모델은 호출 시 rate_limiter가 TPD 여유에 따라 선택 (주 → 폴백)
        logger.info(f"Analyzer initialized (models: {config.GROQ_MODELS})")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=30)
    )
    def analyze_cve(self, cve_data: Dict) -> Dict:
        """CVE 심층 분석. Groq 모델 캐스케이드(compound→mini→gpt-oss→qwen) — 앞 모델의 일일
        한도 소진 또는 오류 시 다음 모델로 넘어간다. 모델별 한도(RPD/TPD)는 rate_limiter가 추적.
        compound는 agentic(웹검색)이라 출력이 순수 JSON이 아닐 수 있어, 파싱 실패 시에도
        다음 모델로 넘겨 견고하게 분석을 확보한다."""
        logger.info(f"Analyzing {cve_data['id']} with AI...")
        prompt = self._build_analysis_prompt(cve_data)
        base = config.GROQ_ANALYSIS_PARAMS

        for model in config.GROQ_MODELS:
            # 이 모델 일일 한도(RPD/TPD) 소진이면 다음 모델로
            if rate_limit_manager.is_tpd_exhausted(model, required_tokens=6000):
                continue
            try:
                rate_limit_manager.check_and_wait("groq")

                api_params = {
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": base["temperature"],
                    "top_p": base["top_p"],
                    "max_completion_tokens": base["max_completion_tokens"],
                }
                # reasoning 파라미터는 모델별로 다름 (compound=미전송, gpt-oss=low, qwen=none)
                reasoning = config.GROQ_MODEL_REASONING.get(model, {})
                if reasoning.get("reasoning_effort"):
                    api_params["reasoning_effort"] = reasoning["reasoning_effort"]
                if reasoning.get("reasoning_format"):
                    api_params["reasoning_format"] = reasoning["reasoning_format"]

                response = self.client.chat.completions.create(**api_params)

                tokens_used = 0
                if hasattr(response, 'usage') and response.usage:
                    tokens_used = response.usage.total_tokens
                rate_limit_manager.record_call("groq", tokens_used=tokens_used, model=model)

                raw_content = (response.choices[0].message.content or "").strip()
                result = self._extract_json(raw_content)

                if result is None or not self._validate_analysis_result(result):
                    # 파싱/검증 실패 → 다음 모델로 재시도 (compound의 비정형 출력 대비)
                    logger.warning(f"{cve_data['id']}: AI 응답 파싱/검증 실패 ({model}) → 다음 모델 시도")
                    continue

                logger.info(f"{cve_data['id']}: Analysis complete (model={model})")
                return result

            except Exception as e:
                error_str = str(e)
                if "429" in error_str or "rate_limit" in error_str.lower():
                    # 일일 한도(TPD/RPD) 소진 → 이 모델 마킹 후 다음 모델
                    if any(t in error_str.lower() for t in ("tokens per day", "tpd", "requests per day", "rpd", "per day")):
                        logger.warning(f"{model} 일일 한도 429 → 다음 모델 전환")
                        rate_limit_manager.handle_429("groq", error_message=error_str, model=model)
                        continue
                    # 분/RPM 429 → 대기 후 tenacity 재시도
                    retry_after = rate_limit_manager.parse_retry_after(error_str)
                    wait_time = retry_after if retry_after else 10
                    logger.warning(f"Groq 429 (RPM/TPM), {wait_time:.1f}초 대기 후 재시도")
                    rate_limit_manager.handle_429("groq", wait_time, error_message=error_str, model=model)
                    raise
                # 네트워크/타임아웃 → tenacity 재시도
                if any(k in error_str.lower() for k in ['timeout', 'connection', 'socket', 'network']):
                    logger.warning(f"{cve_data['id']}: 일시적 에러, 재시도: {e}")
                    raise
                # 그 외(모델별 파라미터 미지원 등) → 다음 모델 시도
                logger.warning(f"{cve_data['id']}: 분석 오류 ({model}: {e}) → 다음 모델 시도")
                continue

        # 모든 Groq 모델 소진/실패 → 규칙 기반 fallback (다음 실행에서 재처리됨)
        logger.warning(f"{cve_data['id']}: 모든 Groq 모델 분석 실패 → fallback 분석")
        return self._fallback_analysis(cve_data)

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
   - Evaluate CIA impact based on the CVSS vector values
   - State what is confirmed by the vector vs what is inferred

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