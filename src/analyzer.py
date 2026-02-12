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
        CVE 심층 분석 (High Reasoning 적용 + 상세 지침 복구 + 한글 출력)
        """
        # [수정] 상세 지침(Constraints)을 기존의 구체적인 버전으로 원복 및 강화
        prompt = f"""
        You are a Senior Security Analyst. Analyze the following CVE deeply.
        
        [Context]
        CVE-ID: {cve_data['id']}
        Description: {cve_data['description']}
        CWE: {', '.join(cve_data.get('cwe', []))}
        CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
        Affected Info: {json.dumps(cve_data.get('affected', []))}

        [Tasks]
        1. **Root Cause**: Identify the technical root cause (e.g., buffer overflow in parser X, missing input validation in API Y).
        2. **Kill Chain Scenario**: Describe the attack flow based on MITRE ATT&CK standards (Initial Access -> Execution -> Impact). Be specific.
        3. **Business Impact**: Assess the impact on CIA (Confidentiality, Integrity, Availability) in business terms (e.g., data breach liability, service outage, reputation loss).
        4. **Mitigation**: Suggest specific remediation steps. If a version is mentioned like "less than 1.2.3", infer the fixed version explicitly (e.g., "Update to 1.2.3 or later").
        5. **Rule Feasibility**: Determine if we can create a specific Snort/Yara rule. 
           - Set to **true** ONLY IF specific indicators (specific file paths, URL parameters, magic bytes, specific function names) are present in the description.
           - Set to **false** if the description is generic (e.g., "unspecified vulnerability", "generic RCE"). **This is crucial to prevent false positives.**

        [Language Restriction]
        - **Translate ALL output values into Korean (한국어).**
        - Keep JSON keys in English (root_cause, etc.).
        - Use professional Korean security terminology (e.g., 'Arbitrary Code Execution' -> '임의 코드 실행').

        [Output Format]
        Return ONLY a raw JSON object with these keys: "root_cause", "scenario", "impact", "mitigation" (list of strings), "rule_feasibility" (boolean).
        """

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                # [수정] 스펙 문서에 따라 주석 해제 (GPT-OSS 120B 지원)
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