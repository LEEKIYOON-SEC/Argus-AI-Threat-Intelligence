import os
import json
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential
import config

class Analyzer:
    def __init__(self):
        self.client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=2, max=10))
    def analyze_cve(self, cve_data):
        """
        CVE 심층 분석 (High Reasoning + Observable Gate + 한글 출력)
        """
        prompt = f"""
        You are a Senior Security Analyst. Analyze the following CVE deeply.
        
        [Context]
        CVE-ID: {cve_data['id']}
        Description: {cve_data['description']}
        CWE: {', '.join(cve_data.get('cwe', []))}
        CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
        Affected Info: {json.dumps(cve_data.get('affected', []))}

        [Tasks]
        1. **Root Cause**: Identify the technical root cause (e.g., buffer overflow in parser X).
        2. **Kill Chain Scenario**: Describe the attack flow based on MITRE ATT&CK standards.
        3. **Business Impact**: Assess the impact on CIA (Confidentiality, Integrity, Availability).
        4. **Mitigation**: Suggest specific remediation steps. Infer fixed versions if possible.
        5. **Rule Feasibility**: Determine if we can create a specific Snort/Yara rule. 
           - **CRITICAL:** Set to **true** ONLY IF specific indicators (file paths, URL parameters, magic bytes, specific function names, log patterns) are clearly present in the description.
           - Set to **false** if the description is generic (e.g., "unspecified vulnerability", "generic RCE", "crash"). **Do NOT hallucinate indicators.**

        [Language & Terminology Constraints]
        - **Translate ALL output values into Korean (한국어).**
        - **KEEP Standard Technical Terms in English or standard Korean Transliteration.**
          - Good: "Reverse Proxy", "리버스 프록시", "SQL Injection", "SQL 인젝션".
          - Bad: "역방향 프록시", "SQL 주입".
        - Keep JSON keys in English.

        [Output Format]
        Return ONLY a raw JSON object with these keys: "root_cause", "scenario", "impact", "mitigation" (list of strings), "rule_feasibility" (boolean).
        """

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_PARAMS["reasoning_effort"], 
                response_format=config.GROQ_PARAMS["response_format"]
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"[ERR] Analyzer Failed: {e}")
            # 재시도 실패 시 기본값 리턴 (프로세스 중단 방지)
            return {
                "root_cause": "분석 실패 (API Error)",
                "scenario": "자동 분석을 수행할 수 없습니다.",
                "impact": "정보 없음",
                "mitigation": ["제조사 권고문 참조"],
                "rule_feasibility": False
            }