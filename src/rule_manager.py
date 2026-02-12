import os
import requests
import tarfile
import io
import re
from groq import Groq
import config

class RuleManager:
    def __init__(self):
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1
        self.snort_cache = []

    def _search_github(self, repo, query):
        print(f"[🔍 검증 로그] GitHub 검색 시작: repo:{repo} {query}")
        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {"Authorization": f"token {self.gh_token}", "Accept": "application/vnd.github.v3+json"}
        try:
            res = requests.get(url, headers=headers, timeout=5)
            if res.status_code == 200 and res.json().get('total_count', 0) > 0:
                item = res.json()['items'][0]
                print(f"[✅ 검증 로그] GitHub 룰 발견! URL: {item['html_url']}")
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                return requests.get(raw_url).text
            print(f"[❌ 검증 로그] GitHub 룰 없음 ({repo})")
            return None
        except Exception as e: 
            print(f"[ERR] GitHub Search Err: {e}")
            return None

    def _fetch_snort_rules(self, cve_id):
        print(f"[🔍 검증 로그] Snort/ET Open 룰셋 메모리 검색 시작: {cve_id}")
        if not self.snort_cache:
            try:
                # print("[INFO] Snort Community Rules 다운로드 중...")
                res = requests.get("https://www.snort.org/downloads/community/community-rules.tar.gz", timeout=15)
                if res.status_code == 200:
                    with tarfile.open(fileobj=io.BytesIO(res.content), mode="r:gz") as tar:
                        for member in tar.getmembers():
                            if "community.rules" in member.name:
                                f = tar.extractfile(member)
                                content = f.read().decode('utf-8', errors='ignore')
                                self.snort_cache.append(content)
                                break
            except Exception as e:
                print(f"[WARN] Failed to fetch Snort Community: {e}")

            try:
                # print("[INFO] ET Open Rules 다운로드 중...")
                res = requests.get("https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules", timeout=15)
                if res.status_code == 200:
                    self.snort_cache.append(res.text)
            except Exception as e:
                print(f"[WARN] Failed to fetch ET Open: {e}")

        for i, ruleset in enumerate(self.snort_cache):
            source_name = "Snort Community" if i == 0 else "ET Open"
            for line in ruleset.splitlines():
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    print(f"[✅ 검증 로그] {source_name}에서 룰 발견!")
                    return line.strip()
        
        print("[❌ 검증 로그] Snort/ET Open에서 룰을 찾지 못함.")
        return None

    def _validate_syntax(self, rule_type, code):
        if not code: return False
        try:
            if rule_type == "Snort":
                if not re.match(r'^(alert|log|pass|drop|reject|sdrop)\s', code.strip()): return False
                if code.count('(') != code.count(')'): return False
                if "msg:" not in code or "sid:" not in code: return False
                return True
            elif rule_type == "Yara":
                if not code.strip().startswith("rule "): return False
                if code.count('{') != code.count('}'): return False
                if "condition:" not in code: return False
                return True
            elif rule_type == "Sigma":
                required = ["title:", "logsource:", "detection:", "condition:"]
                for req in required:
                    if req not in code: return False
                return True
        except: return False
        return False

    def _generate_ai_rule(self, rule_type, cve_data):
        print(f"[🧠 검증 로그] AI({rule_type}) 생성 시도 중...")
        prompt = f"""
        You are a Senior Security Engineer. Write a valid {rule_type} detection rule for {cve_data['id']}.
        
        [Context]
        Description: {cve_data['description']}
        Vector: {cve_data['cvss_vector']}

        [Requirements]
        - **Snort**: Must start with 'alert tcp ...', include 'msg', 'sid', 'rev'.
        - **Yara**: Must include 'meta', 'strings', 'condition'.
        - **Sigma**: Must be valid YAML with 'title', 'logsource', 'detection', 'condition'.
        - Output ONLY the code block. No markdown, no explanations.
        - If you cannot create a valid rule due to lack of information, return 'SKIP'.
        """
        
        try:
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                # [수정] 고추론 모델 사용 (사용자 요청 고정)
                reasoning_effort=config.GROQ_PARAMS["reasoning_effort"] 
            )
            
            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip()
            
            if content == "SKIP": 
                print(f"[⛔ 검증 로그] AI가 {rule_type} 생성을 SKIP 함 (정보 부족)")
                return None

            if self._validate_syntax(rule_type, content):
                print(f"[✅ 검증 로그] AI {rule_type} 룰 생성 및 검증 성공")
                return content
            else:
                print(f"[WARN] 🚨 Syntax Error in AI {rule_type} Rule. Discarded.")
                return None
        except Exception as e:
            print(f"[ERR] AI Rule Gen Failed: {e}")
            return None

    def get_rules(self, cve_data, feasibility):
        rules = {"sigma": None, "snort": None, "yara": None}
        cve_id = cve_data['id']

        public_sigma = self._search_github("SigmaHQ/sigma", f"{cve_id} filename:.yml")
        if public_sigma:
            rules['sigma'] = {"code": public_sigma, "source": "Public (SigmaHQ)"}
        else:
            ai_sigma = self._generate_ai_rule("Sigma", cve_data)
            if ai_sigma:
                rules['sigma'] = {"code": ai_sigma, "source": "AI Generated (Verified)"}

        public_snort = self._fetch_snort_rules(cve_id)
        if public_snort:
            rules['snort'] = {"code": public_snort, "source": "Public (Snort/ET)"}
        elif feasibility:
            ai_snort = self._generate_ai_rule("Snort", cve_data)
            if ai_snort:
                rules['snort'] = {"code": ai_snort, "source": "AI Generated (Verified)"}
        else:
             print(f"[ℹ️ 검증 로그] Snort 생성 생략 (Feasibility: False)")

        public_yara = self._search_github("Yara-Rules/rules", f"{cve_id} filename:.yar")
        if public_yara:
            rules['yara'] = {"code": public_yara, "source": "Public (Yara-Rules)"}
        elif feasibility:
            ai_yara = self._generate_ai_rule("Yara", cve_data)
            if ai_yara:
                rules['yara'] = {"code": ai_yara, "source": "AI Generated (Verified)"}
        else:
             print(f"[ℹ️ 검증 로그] Yara 생성 생략 (Feasibility: False)")

        return rules