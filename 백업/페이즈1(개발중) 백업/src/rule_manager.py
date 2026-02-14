import os
import requests
import tarfile
import io
import re
import yaml
import yara
import docker
import tempfile
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_fixed
import config

class RuleManager:
    def __init__(self):
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1
        self.snort_cache = []
        
        # [Docker 연결] GitHub Actions 환경 대응
        self.docker_client = None
        if config.DOCKER_CONFIG["enabled"]:
            try:
                self.docker_client = docker.from_env()
                # 이미지 존재 여부 확인 및 Pull
                try:
                    self.docker_client.images.get(config.DOCKER_CONFIG["snort_image"])
                except docker.errors.ImageNotFound:
                    print(f"[INFO] Pulling Docker Image: {config.DOCKER_CONFIG['snort_image']}...")
                    self.docker_client.images.pull(config.DOCKER_CONFIG["snort_image"])
                print("[INFO] Docker Client Connected for Rule Validation")
            except Exception as e:
                print(f"[WARN] Docker unavailable: {e}. Validation will leverage libraries.")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _search_github(self, repo, query):
        print(f"[🔍 검증 로그] GitHub 검색 시작: repo:{repo} {query}")
        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {"Authorization": f"token {self.gh_token}", "Accept": "application/vnd.github.v3+json"}
        
        try:
            res = requests.get(url, headers=headers, timeout=10)
            if res.status_code == 200 and res.json().get('total_count', 0) > 0:
                item = res.json()['items'][0]
                print(f"[✅ 검증 로그] GitHub 룰 발견! URL: {item['html_url']}")
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                return requests.get(raw_url).text
        except Exception as e:
            print(f"[ERR] GitHub Search Error: {e}")
        
        print(f"[❌ 검증 로그] GitHub 룰 없음 ({repo})")
        return None

    def _fetch_snort_rules(self, cve_id):
        # (기존 메모리 캐싱 로직 유지)
        print(f"[🔍 검증 로그] Snort/ET Open 룰셋 메모리 검색 시작: {cve_id}")
        if not self.snort_cache:
            try:
                res = requests.get("https://www.snort.org/downloads/community/community-rules.tar.gz", timeout=15)
                if res.status_code == 200:
                    with tarfile.open(fileobj=io.BytesIO(res.content), mode="r:gz") as tar:
                        for member in tar.getmembers():
                            if "community.rules" in member.name:
                                f = tar.extractfile(member)
                                content = f.read().decode('utf-8', errors='ignore')
                                self.snort_cache.append(content)
                                break
            except: pass

            try:
                res = requests.get("https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules", timeout=15)
                if res.status_code == 200:
                    self.snort_cache.append(res.text)
            except: pass

        for i, ruleset in enumerate(self.snort_cache):
            source_name = "Snort Community" if i == 0 else "ET Open"
            for line in ruleset.splitlines():
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    print(f"[✅ 검증 로그] {source_name}에서 룰 발견!")
                    return line.strip()
        print("[❌ 검증 로그] Snort/ET Open에서 룰을 찾지 못함.")
        return None

    # -------------------------------------------------------------------------
    # [핵심] 실제 엔진 기반 검증 로직 (Library & Docker)
    # -------------------------------------------------------------------------
    def _validate_sigma(self, code):
        """PyYAML 파싱 및 구조 검증"""
        try:
            data = yaml.safe_load(code)
            if not isinstance(data, dict): return False
            required = ['title', 'logsource', 'detection', 'condition']
            if not all(k in data for k in required): return False
            if 'product' not in data['logsource'] and 'category' not in data['logsource']: return False
            return True
        except: return False

    def _validate_yara(self, code):
        """yara-python 컴파일 검증"""
        try:
            yara.compile(source=code)
            return True
        except: return False

    def _validate_snort_docker(self, code):
        """Docker 기반 Snort3 실행 검증"""
        if not self.docker_client:
            # Fallback: Regex Validation
            return re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s', code.strip(), re.IGNORECASE)
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.rules', delete=False) as temp:
                temp.write(code)
                temp_path = temp.name
            
            # GHA Runner의 /tmp를 bind mount
            self.docker_client.containers.run(
                image=config.DOCKER_CONFIG["snort_image"],
                command=f"snort --warn-all -c /tmp/test.rules", # Config 없이 룰 파일만 문법 체크 시도
                volumes={temp_path: {'bind': '/tmp/test.rules', 'mode': 'ro'}},
                remove=True, stderr=True, stdout=True
            )
            return True
        except docker.errors.ContainerError:
            # Snort 실행 실패 (문법 에러 등)
            return False
        except Exception as e:
            print(f"[WARN] Docker validation error: {e}")
            return re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s', code.strip(), re.IGNORECASE)
        finally:
            if os.path.exists(temp_path): os.remove(temp_path)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _generate_ai_rule(self, rule_type, cve_data):
        print(f"[🧠 검증 로그] AI({rule_type}) 생성 시도 중...")
        
        prompt = f"""
        You are a Senior Security Engineer. Write a valid {rule_type} detection rule for {cve_data['id']}.
        
        [Context]
        Description: {cve_data['description']}
        Vector: {cve_data['cvss_vector']}

        [Requirements]
        - **Observables Gate:** If no concrete indicator (path, param, bytes, log pattern) exists in context, return 'SKIP'.
        - **No Hallucination:** Do not invent log fields or paths.
        - **Structure:** Follow standard syntax strictly.
        - Output ONLY the raw code block.

        [Templates]
        """
        if rule_type == "Snort":
            prompt += "- alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS ... (msg:'...'; sid:1000001;)"
        elif rule_type == "Yara":
            prompt += "- rule CVE_ID { meta: ... strings: ... condition: ... }"
        elif rule_type == "Sigma":
            prompt += "- title: ... logsource: ... detection: ... condition: ..."

        try:
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_PARAMS["temperature"],
                top_p=config.GROQ_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_PARAMS["reasoning_effort"]
            )
            
            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip()
            
            if content == "SKIP": 
                print(f"[⛔ 검증 로그] AI가 {rule_type} 생성을 SKIP 함 (근거 부족)")
                return None

            is_valid = False
            if rule_type == "Snort": is_valid = self._validate_snort_docker(content)
            elif rule_type == "Yara": is_valid = self._validate_yara(content)
            elif rule_type == "Sigma": is_valid = self._validate_sigma(content)

            if is_valid:
                print(f"[✅ 검증 로그] AI {rule_type} 룰 생성 및 엔진 검증 성공")
                return content
            else:
                print(f"\n[WARN] 🚨 Validation Failed for AI {rule_type} Rule.")
                print("="*20 + " [FAILED CODE] " + "="*20)
                print(content)
                print("="*20 + " [END] " + "="*20 + "\n")
                return None
        except Exception as e:
            print(f"[ERR] AI Rule Gen Failed: {e}")
            raise e # Retry

    def get_rules(self, cve_data, feasibility):
        rules = {"sigma": None, "snort": None, "yara": None}
        cve_id = cve_data['id']

        # Sigma
        public_sigma = self._search_github("SigmaHQ/sigma", f"{cve_id} filename:.yml")
        if public_sigma: rules['sigma'] = {"code": public_sigma, "source": "Public (SigmaHQ)"}
        else:
            ai_sigma = self._generate_ai_rule("Sigma", cve_data)
            if ai_sigma: rules['sigma'] = {"code": ai_sigma, "source": "AI Generated (Validated)"}

        # Snort
        public_snort = self._fetch_snort_rules(cve_id)
        if public_snort: rules['snort'] = {"code": public_snort, "source": "Public (Snort/ET)"}
        elif feasibility:
            ai_snort = self._generate_ai_rule("Snort", cve_data)
            if ai_snort: rules['snort'] = {"code": ai_snort, "source": "AI Generated (Container Validated)"}
        
        # Yara
        public_yara = self._search_github("Yara-Rules/rules", f"{cve_id} filename:.yar")
        if public_yara: rules['yara'] = {"code": public_yara, "source": "Public (Yara-Rules)"}
        elif feasibility:
            ai_yara = self._generate_ai_rule("Yara", cve_data)
            if ai_yara: rules['yara'] = {"code": ai_yara, "source": "AI Generated (Compiled)"}

        return rules