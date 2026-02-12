import os
import json
from groq import Groq
import config

class Analyzer:
    def __init__(self):
        self.client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1

    def analyze_cve(self, cve_data):
        """
        CVE 심층 분석 (High Reasoning + 용어 교정 + 한글 출력)
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
        2. **Kill Chain Scenario**: Describe the attack flow based on MITRE ATT&CK standards (Initial Access -> Execution -> Impact).
        3. **Business Impact**: Assess the impact on CIA (Confidentiality, Integrity, Availability) in business terms.
        4. **Mitigation**: Suggest specific remediation steps. Infer fixed versions if possible.
        5. **Rule Feasibility**: Determine if we can create a specific Snort/Yara rule. 
           - Set to **true** ONLY IF specific indicators (file paths, params, bytes) are present.
           - Set to **false** if the description is generic.

        [Language & Terminology Constraints]
        - **Translate ALL output values into Korean (한국어).**
        - **KEEP Standard Technical Terms in English or standard Korean Transliteration.** - **Good:** "Reverse Proxy", "리버스 프록시", "SQL Injection", "SQL 인젝션", "Buffer Overflow", "버퍼 오버플로우".
          - **Bad (Do NOT Use):** "역방향 프록시", "SQL 주입", "버퍼 초과".
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
                # [수정] 고추론 모델 사용 (사용자 요청 고정)
                reasoning_effort=config.GROQ_PARAMS["reasoning_effort"], 
                response_format=config.GROQ_PARAMS["response_format"]
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            print(f"[ERR] Analyzer Failed: {e}")
            return {
                "root_cause": "분석 실패",
                "scenario": "자동 분석을 수행할 수 없습니다.",
                "impact": "정보 없음",
                "mitigation": ["제조사 권고문 참조"],
                "rule_feasibility": False
            }