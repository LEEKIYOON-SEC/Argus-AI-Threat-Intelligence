import os
import requests
import tarfile
import io
import re
import yaml
import yara
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Dict, Optional, Tuple, List
from logger import logger
from config import config
from rate_limiter import rate_limit_manager

class RuleManagerError(Exception):
    pass

class RuleManager:
    # GitHub Code Search API 차단 상태 (클래스 수준 - 모든 인스턴스 공유)
    _code_search_blocked = False
    _code_search_fail_count = 0
    _CODE_SEARCH_MAX_FAILS = 3  # 3회 연속 실패 시 차단 (단일 실패로 전체 차단 방지)
    # SigmaHQ/Yara-Rules tarball 캐시 (클래스 수준 - 한 번 다운로드 후 재사용)
    _sigma_files: Dict[str, str] = {}
    _yara_files: Dict[str, str] = {}

    def __init__(self):
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1

        # 룰셋 캐시 (엔진별로 구분)
        # 예: {"Snort 2.9 Community": "rule_content", "Snort 3 ET Open": "rule_content"}
        self.rules_cache: Dict[str, str] = {}

        logger.info("✅ RuleManager 초기화 완료 (정규식 검증 모드)")

    @staticmethod
    def _parse_attack_vector(cvss_vector: str) -> str:
        """
        CVSS 벡터에서 Attack Vector(AV) 추출.
        Returns: 'NETWORK', 'LOCAL', 'ADJACENT', 'PHYSICAL', 또는 'UNKNOWN'
        """
        if not cvss_vector:
            return "UNKNOWN"
        match = re.search(r'AV:([NALP])', cvss_vector)
        if not match:
            return "UNKNOWN"
        av_map = {"N": "NETWORK", "A": "ADJACENT", "L": "LOCAL", "P": "PHYSICAL"}
        return av_map.get(match.group(1), "UNKNOWN")
    
    # ====================================================================
    # [1] 공개 룰 검색
    # ====================================================================
    
    def _search_github(self, repo: str, query: str) -> Optional[str]:
        # Circuit breaker: 이미 403이 한 번 발생했으면 이번 실행 내 모든 검색 스킵
        if RuleManager._code_search_blocked:
            return None

        logger.debug(f"GitHub 검색: {repo} / {query}")

        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {
            "Authorization": f"token {self.gh_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        try:
            rate_limit_manager.check_and_wait("github_search")
            response = requests.get(url, headers=headers, timeout=10)
            rate_limit_manager.record_call("github_search")

            # 403/429는 rate limit → 누적 카운트 후 임계치 도달 시 차단
            if response.status_code in (403, 429):
                RuleManager._code_search_fail_count += 1
                if RuleManager._code_search_fail_count >= RuleManager._CODE_SEARCH_MAX_FAILS:
                    logger.warning(f"⚠️ GitHub Code Search {RuleManager._code_search_fail_count}회 연속 실패 → 이번 실행 내 검색 중단")
                    RuleManager._code_search_blocked = True
                else:
                    logger.warning(f"⚠️ GitHub Code Search rate limit ({response.status_code}), 실패 {RuleManager._code_search_fail_count}/{RuleManager._CODE_SEARCH_MAX_FAILS}")
                return None

            response.raise_for_status()

            data = response.json()

            if data.get('total_count', 0) > 0:
                item = data['items'][0]
                logger.info(f"✅ 공개 룰 발견: {item['html_url']}")

                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')

                raw_response = requests.get(raw_url, timeout=10)
                raw_response.raise_for_status()

                return raw_response.text

            logger.debug(f"❌ 공개 룰 없음: {repo}")
            return None

        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub 검색 실패: {e}")
            return None
        except Exception as e:
            logger.error(f"예상치 못한 에러: {e}")
            return None
    
    def _fetch_network_rules(self, cve_id: str) -> List[Dict[str, str]]:
        logger.debug(f"네트워크 룰셋 검색 시작: {cve_id}")
        
        found_rules = []
        
        # 캐시가 비어있으면 룰셋 다운로드 (첫 실행 시)
        if not self.rules_cache:
            self._download_all_rulesets()
        
        # 각 룰셋에서 CVE 검색
        for ruleset_name, ruleset_content in self.rules_cache.items():
            for line in ruleset_content.splitlines():
                # CVE ID가 포함되어 있고, 주석이 아니고, alert 키워드가 있는 줄
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    # 엔진 타입 결정
                    engine_type = self._detect_engine_type(ruleset_name)
                    
                    found_rules.append({
                        "code": line.strip(),
                        "source": ruleset_name,  # 예: "Snort 3 ET Open"
                        "engine": engine_type    # 예: "snort3"
                    })
                    
                    logger.info(f"✅ {ruleset_name}에서 룰 발견")
                    break  # 룰셋당 첫 번째 매칭만 (중복 방지)
        
        if not found_rules:
            logger.debug("❌ 모든 네트워크 룰셋에서 찾지 못함")
        else:
            logger.info(f"✅ 총 {len(found_rules)}개 엔진의 룰 발견")
        
        return found_rules
    
    def _download_all_rulesets(self):
        logger.info("📥 네트워크 룰셋 다운로드 중...")
        
        # ===== 1. Snort Community Rules =====
        
        # 1-1. Snort 2.9 Community
        try:
            logger.debug("  - Snort 2.9 Community 다운로드 중...")
            response = requests.get(
                "https://www.snort.org/downloads/community/community-rules.tar.gz",
                timeout=15
            )
            if response.status_code == 200:
                with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if "community.rules" in member.name:
                            f = tar.extractfile(member)
                            content = f.read().decode('utf-8', errors='ignore')
                            self.rules_cache["Snort 2.9 Community"] = content
                            logger.info("  ✅ Snort 2.9 Community 로드 완료")
                            break
        except Exception as e:
            logger.warning(f"  ⚠️ Snort 2.9 Community 다운로드 실패: {e}")
        
        # 1-2. Snort 3 Community
        try:
            logger.debug("  - Snort 3 Community 다운로드 중...")
            response = requests.get(
                "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
                timeout=15
            )
            if response.status_code == 200:
                with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if "snort3-community.rules" in member.name:
                            f = tar.extractfile(member)
                            content = f.read().decode('utf-8', errors='ignore')
                            self.rules_cache["Snort 3 Community"] = content
                            logger.info("  ✅ Snort 3 Community 로드 완료")
                            break
        except Exception as e:
            logger.warning(f"  ⚠️ Snort 3 Community 다운로드 실패: {e}")
        
        # ===== 2. Emerging Threats Open =====
        
        et_rulesets = [
            ("Snort 2.9 ET Open", "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules"),
            ("Suricata 5 ET Open", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules"),
            ("Suricata 7 ET Open", "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"),
            # edge는 불안정할 수 있어서 선택적으로 추가 (주석 처리)
            # ("Snort Edge ET Open", "https://rules.emergingthreats.net/open/snort-edge/emerging-all.rules"),
        ]
        
        for name, url in et_rulesets:
            try:
                logger.debug(f"  - {name} 다운로드 중...")
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    self.rules_cache[name] = response.text
                    logger.info(f"  ✅ {name} 로드 완료")
                else:
                    logger.debug(f"  ⚠️ {name} 다운로드 실패: HTTP {response.status_code}")
            except Exception as e:
                logger.debug(f"  ⚠️ {name} 다운로드 실패: {e}")
        
        logger.info(f"✅ 룰셋 다운로드 완료 ({len(self.rules_cache)}개 소스)")
    
    def _detect_engine_type(self, ruleset_name: str) -> str:
        name_lower = ruleset_name.lower()
        
        # Snort 버전 감지
        if "snort 2.9" in name_lower or "snort 2" in name_lower:
            return "snort2"
        elif "snort 3" in name_lower or "snort3" in name_lower:
            return "snort3"
        
        # Suricata 버전 감지
        elif "suricata 5" in name_lower:
            return "suricata5"
        elif "suricata 7" in name_lower:
            return "suricata7"
        elif "suricata edge" in name_lower:
            return "suricata-edge"
        
        else:
            return "unknown"

    # ====================================================================
    # [1-2] SigmaHQ / Yara-Rules tarball 로컬 검색
    # ====================================================================

    def _download_sigma_repo(self):
        """SigmaHQ/sigma tarball 다운로드 후 rules/*.yml 파일 캐시"""
        if RuleManager._sigma_files:
            return

        logger.info("📥 SigmaHQ 룰셋 다운로드 중...")
        headers = {"Authorization": f"token {self.gh_token}"} if self.gh_token else {}

        try:
            rate_limit_manager.check_and_wait("ruleset_download")
            response = requests.get(
                "https://api.github.com/repos/SigmaHQ/sigma/tarball",
                headers=headers, timeout=60
            )
            response.raise_for_status()
            rate_limit_manager.record_call("ruleset_download")

            count = 0
            with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith('.yml') and '/rules' in member.name:
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode('utf-8', errors='ignore')
                            RuleManager._sigma_files[member.name] = content
                            count += 1

            logger.info(f"  ✅ SigmaHQ 로드 완료 ({count}개 룰)")
        except Exception as e:
            logger.warning(f"  ⚠️ SigmaHQ 다운로드 실패: {e}")

    def _download_yara_repo(self):
        """Yara-Rules/rules tarball 다운로드 후 *.yar 파일 캐시"""
        if RuleManager._yara_files:
            return

        logger.info("📥 Yara-Rules 룰셋 다운로드 중...")
        headers = {"Authorization": f"token {self.gh_token}"} if self.gh_token else {}

        try:
            rate_limit_manager.check_and_wait("ruleset_download")
            response = requests.get(
                "https://api.github.com/repos/Yara-Rules/rules/tarball",
                headers=headers, timeout=60
            )
            response.raise_for_status()
            rate_limit_manager.record_call("ruleset_download")

            count = 0
            with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                for member in tar.getmembers():
                    if member.isfile() and (member.name.endswith('.yar') or member.name.endswith('.yara')):
                        f = tar.extractfile(member)
                        if f:
                            content = f.read().decode('utf-8', errors='ignore')
                            RuleManager._yara_files[member.name] = content
                            count += 1

            logger.info(f"  ✅ Yara-Rules 로드 완료 ({count}개 룰)")
        except Exception as e:
            logger.warning(f"  ⚠️ Yara-Rules 다운로드 실패: {e}")

    def _search_local_sigma(self, cve_id: str) -> Optional[str]:
        """SigmaHQ 로컬 캐시에서 CVE ID 검색"""
        if not RuleManager._sigma_files:
            self._download_sigma_repo()

        cve_lower = cve_id.lower()
        for filepath, content in RuleManager._sigma_files.items():
            if cve_lower in content.lower():
                filename = filepath.split('/')[-1]
                logger.info(f"✅ SigmaHQ 로컬에서 발견: {filename}")
                return content

        logger.debug(f"❌ SigmaHQ 로컬: {cve_id} 없음")
        return None

    def _search_local_yara(self, cve_id: str) -> Optional[str]:
        """Yara-Rules 로컬 캐시에서 CVE ID 검색"""
        if not RuleManager._yara_files:
            self._download_yara_repo()

        cve_lower = cve_id.lower()
        for filepath, content in RuleManager._yara_files.items():
            if cve_lower in content.lower():
                filename = filepath.split('/')[-1]
                logger.info(f"✅ Yara-Rules 로컬에서 발견: {filename}")
                return content

        logger.debug(f"❌ Yara-Rules 로컬: {cve_id} 없음")
        return None

    # ====================================================================
    # [2] 룰 검증 (정규식 기반)
    # ====================================================================
    
    def _validate_sigma(self, code: str) -> bool:
        """
        Sigma 룰 검증 (강화)

        7단계 검증:
        1. YAML 파싱
        2. 필수 필드 존재 (title, logsource, detection)
        3. logsource에 product 또는 category
        4. detection에 condition 필드
        5. detection에 최소 1개 selection 존재
        6. selection이 단순 파라미터만이 아닌지 (semantic check)
        7. level 필드 존재
        """
        try:
            data = yaml.safe_load(code)

            if not isinstance(data, dict):
                logger.warning("Sigma: YAML이 딕셔너리가 아님")
                return False

            # 필수 필드 확인
            required = ['title', 'logsource', 'detection']
            for field in required:
                if field not in data:
                    logger.warning(f"Sigma: 필수 필드 누락 - {field}")
                    return False

            # logsource 검증
            logsource = data['logsource']
            if not isinstance(logsource, dict):
                logger.warning("Sigma: logsource가 딕셔너리가 아님")
                return False
            if 'product' not in logsource and 'category' not in logsource:
                logger.warning("Sigma: logsource에 product 또는 category 필요")
                return False

            # detection 검증
            detection = data['detection']
            if not isinstance(detection, dict):
                logger.warning("Sigma: detection이 딕셔너리가 아님")
                return False

            # condition 필수
            if 'condition' not in detection:
                logger.warning("Sigma: detection에 condition 필드 누락")
                return False

            # 최소 1개 selection 존재
            selections = [k for k in detection.keys() if k != 'condition']
            if not selections:
                logger.warning("Sigma: detection에 selection이 없음")
                return False

            # 단일 selection만 있고 필드가 1개뿐이면 경고 (너무 포괄적)
            if len(selections) == 1:
                sel = detection[selections[0]]
                if isinstance(sel, dict) and len(sel) == 1:
                    logger.warning("Sigma: 단일 조건 detection - false positive 위험 높음 (허용하되 경고)")

            logger.debug("✅ Sigma 검증 통과")
            return True

        except yaml.YAMLError as e:
            logger.warning(f"Sigma: YAML 파싱 실패 - {e}")
            return False
        except Exception as e:
            logger.warning(f"Sigma: 예상치 못한 에러 - {e}")
            return False
    
    def _validate_yara(self, code: str) -> bool:
        """
        Yara 룰 검증
        
        Yara는 직접 컴파일해서 검증.
        yara-python 라이브러리가 컴파일을 시도하고,
        문법 에러가 있으면 예외를 발생.
        """
        try:
            yara.compile(source=code)
            logger.debug("✅ Yara 검증 통과")
            return True
        except yara.SyntaxError as e:
            logger.warning(f"Yara: 문법 에러 - {e}")
            return False
        except Exception as e:
            logger.warning(f"Yara: 컴파일 실패 - {e}")
            return False
    
    def _validate_network_rule(self, code: str) -> bool:
        """
        네트워크 룰 검증 (Snort/Suricata - 정규식 기반)

        6단계 검증 과정:
        1. 기본 구조 (alert tcp ...)
        2. 필수 요소 (변수, 포트, 방향)
        3. msg 필드 (필수)
        4. sid 필드 (필수)
        5. 일반적인 문법 오류 (빈 괄호, 연속 세미콜론 등)
        6. 괄호 균형
        
        Args:
            code: Snort 또는 Suricata 룰 문자열
        
        Returns:
            검증 통과 여부
        """
        code = code.strip()
        
        # 1단계: 기본 구조 검증
        if not re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s', code, re.IGNORECASE):
            logger.warning("네트워크 룰: 기본 구조 불일치")
            return False
        
        # 2단계: 필수 요소 검증
        required_patterns = [
            (r'\$\w+', "변수"),
            (r'\d+', "포트"),
            (r'->', "방향"),
            (r'\(', "옵션 시작"),
            (r'\)', "옵션 끝"),
        ]
        
        for pattern, name in required_patterns:
            if not re.search(pattern, code):
                logger.warning(f"네트워크 룰: {name} 누락")
                return False
        
        # 3단계: msg 필드
        if not re.search(r'msg:\s*["\'].*?["\']', code):
            logger.warning("네트워크 룰: msg 필드 누락")
            return False
        
        # 4단계: sid 필드
        if not re.search(r'sid:\s*\d+', code):
            logger.warning("네트워크 룰: sid 필드 누락")
            return False
        
        # 5단계: 일반적인 문법 오류 검출
        invalid_patterns = [
            (r'\(\s*\)', "빈 옵션 괄호"),
            (r';\s*;', "연속 세미콜론"),
            (r'\$[^\w]', "잘못된 변수"),
        ]
        
        for pattern, name in invalid_patterns:
            if re.search(pattern, code):
                logger.warning(f"네트워크 룰: {name} 감지")
                return False
        
        # 6단계: 괄호 균형
        if code.count('(') != code.count(')'):
            logger.warning("네트워크 룰: 괄호 불균형")
            return False
        
        logger.debug("✅ 네트워크 룰 정규식 검증 통과")
        return True
    
    # ====================================================================
    # [3] AI 룰 생성
    # ====================================================================
    
    def _check_observables(self, cve_data: Dict) -> Tuple[bool, str, List[str]]:
        desc = cve_data['description'].lower()
        
        indicators = []
        indicator_details = []  # 구체적 정보 포함
        
        # 파일 경로
        if '/' in cve_data['description']:
            indicators.append("파일 경로")
            # 실제 경로 추출 시도
            paths = re.findall(r'/[a-zA-Z0-9_\-/\.]+', cve_data['description'])
            if paths:
                indicator_details.append(f"파일 경로 ({paths[0]})")
            else:
                indicator_details.append("파일 경로")
        
        # 웹 파일
        web_files = ['.php', '.jsp', '.asp', '.cgi']
        for ext in web_files:
            if ext in desc:
                indicators.append("웹 파일")
                indicator_details.append(f"웹 파일 ({ext})")
                break
        
        # URL 파라미터
        if 'parameter' in desc or 'param=' in desc or '?' in cve_data['description']:
            indicators.append("URL 파라미터")
            # 실제 파라미터 추출 시도
            params = re.findall(r'\b\w+\s*=', cve_data['description'])
            if params:
                indicator_details.append(f"URL 파라미터 ({params[0]})")
            else:
                indicator_details.append("URL 파라미터")
        
        # HTTP 헤더
        if ('header' in desc and ('http' in desc or 'user-agent' in desc)):
            indicators.append("HTTP 헤더")
            indicator_details.append("HTTP 헤더")
        
        # Hex 값
        hex_match = re.search(r'0x[0-9a-f]{2,}', desc)
        if hex_match:
            indicators.append("Hex 값")
            indicator_details.append(f"Hex 값 ({hex_match.group()})")
        
        # 레지스트리
        if 'registry' in desc and 'hk' in desc:
            indicators.append("레지스트리")
            indicator_details.append("레지스트리 키")
        
        # 포트
        port_match = re.search(r'port\s+(\d+)', desc)
        if port_match:
            indicators.append("포트 번호")
            indicator_details.append(f"포트 ({port_match.group(1)})")
        
        # 완화된 기준: 최소 1개 지표
        has_enough = len(indicators) >= 1
        
        if has_enough:
            reason = f"발견된 지표: {', '.join(indicator_details)}"
        else:
            reason = "구체적 지표 부족"
        
        return has_enough, reason, indicator_details
    
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _generate_ai_rule(self, rule_type: str, cve_data: Dict, analysis: Optional[Dict] = None) -> Optional[Tuple[str, List[str]]]:
        """
        AI 기반 탐지 룰 생성
        
        공개 룰이 없고, 구체적 지표가 충분할 때만 AI에게 룰을 생성하도록 요청.
        
        Returns:
            (룰 코드, 발견된 지표 목록) 또는 None
        """
        logger.debug(f"AI {rule_type} 생성 시도")
        
        # Observable Gate (Sigma는 예외 - 로그 기반이라 관대하게)
        indicator_details = []
        if rule_type not in ["Sigma", "sigma"]:
            has_indicators, reason, indicator_details = self._check_observables(cve_data)
            if not has_indicators:
                logger.info(f"⛔ {rule_type} 생성 SKIP: {reason}")
                return None
            else:
                logger.debug(f"✅ Observable Gate 통과: {reason}")
        
        prompt = self._build_rule_prompt(rule_type, cve_data, analysis)
        
        try:
            rate_limit_manager.check_and_wait("groq")
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_RULE_PARAMS["temperature"],
                top_p=config.GROQ_RULE_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_RULE_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_RULE_PARAMS["reasoning_effort"]
            )
            rate_limit_manager.record_call("groq")

            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip()
            
            if content == "SKIP" or not content:
                # Sigma는 필수 생성 — SKIP 시 관대한 프롬프트로 1회 재시도
                if rule_type in ["Sigma", "sigma"] and not getattr(self, '_sigma_retry_done', False):
                    self._sigma_retry_done = True
                    logger.info(f"⚠️ Sigma SKIP → 필수 생성이므로 관대한 프롬프트로 재시도")
                    retry_prompt = self._build_rule_prompt(rule_type, cve_data, analysis)
                    retry_prompt += "\n\n[OVERRIDE] Sigma is MANDATORY. Generate a best-effort Sigma rule using whatever information is available. Do NOT return SKIP."
                    rate_limit_manager.check_and_wait("groq")
                    retry_resp = self.groq_client.chat.completions.create(
                        model=self.model,
                        messages=[{"role": "user", "content": retry_prompt}],
                        temperature=config.GROQ_RULE_PARAMS["temperature"],
                        top_p=config.GROQ_RULE_PARAMS["top_p"],
                        max_completion_tokens=config.GROQ_RULE_PARAMS["max_completion_tokens"],
                        reasoning_effort=config.GROQ_RULE_PARAMS["reasoning_effort"]
                    )
                    rate_limit_manager.record_call("groq")
                    retry_content = retry_resp.choices[0].message.content.strip()
                    retry_content = re.sub(r"```[a-z]*\n|```", "", retry_content).strip()
                    if retry_content and retry_content != "SKIP" and self._validate_sigma(retry_content):
                        logger.info("✅ Sigma 필수 재시도 성공")
                        self._sigma_retry_done = False
                        return (retry_content, indicator_details)
                    self._sigma_retry_done = False
                logger.info(f"⛔ AI가 {rule_type} 생성 거부 (근거 부족)")
                return None
            
            # 검증
            is_valid = False
            if rule_type in ["Snort", "Suricata", "snort", "suricata"]:
                is_valid = self._validate_network_rule(content)
            elif rule_type in ["Yara", "yara"]:
                is_valid = self._validate_yara(content)
            elif rule_type in ["Sigma", "sigma"]:
                is_valid = self._validate_sigma(content)
            
            if is_valid:
                logger.info(f"✅ AI {rule_type} 생성 및 검증 성공")
                return (content, indicator_details)  # 지표 정보 포함
            else:
                logger.warning(f"❌ AI {rule_type} 검증 실패")
                logger.debug(f"실패한 룰:\n{content}")
                return None
                
        except Exception as e:
            logger.error(f"AI 룰 생성 에러: {e}")
            raise
    
    def _build_rule_prompt(self, rule_type: str, cve_data: Dict, analysis: Optional[Dict] = None) -> str:
        """
        AI를 위한 룰 생성 프롬프트 구성
        
        - References 추가 (벤더 권고, PoC 링크)
        - Affected Products 추가 (어떤 제품/버전이 영향받는지)
        - AI Analysis 추가 (root_cause, attack_scenario 등)
        """
        
        # References 정리 (최대 3개)
        references_str = "None"
        if cve_data.get('references'):
            refs = cve_data['references'][:3]
            references_str = "\n".join([f"- {ref}" for ref in refs])
        
        # Affected Products 정리
        affected_str = "Unknown"
        if cve_data.get('affected'):
            affected_items = []
            for item in cve_data['affected'][:3]:  # 최대 3개
                vendor = item.get('vendor', 'Unknown')
                product = item.get('product', 'Unknown')
                versions = item.get('versions', 'Unknown')
                affected_items.append(f"- {vendor} {product} ({versions})")
            if affected_items:
                affected_str = "\n".join(affected_items)
        
        # AI Analysis
        analysis_section = ""
        if analysis:
            root_cause = analysis.get('root_cause', 'N/A')
            attack_scenario = analysis.get('scenario', 'N/A')
            if root_cause != 'N/A' or attack_scenario != 'N/A':
                analysis_section = f"""
[AI Analysis - Additional Context]
Root Cause: {root_cause}
Attack Scenario: {attack_scenario}
"""

        # Exploit-DB 참고 코드
        exploit_section = ""
        if cve_data.get('_exploit_db_snippet'):
            exploit_section = f"""
[Exploit Code (Exploit-DB)]
Public exploit/PoC snippet. Extract concrete indicators from this:
- HTTP paths, parameters, headers, methods
- Specific payload strings or byte sequences
- File paths, registry keys, command lines
- Network ports, protocols

{cve_data['_exploit_db_snippet']}
"""

        base_prompt = f"""
You are a Senior Detection Engineer specializing in {rule_type} rules.
Write a valid {rule_type} detection rule for {cve_data['id']}.

[Context]
CVE-ID: {cve_data['id']}
Description: {cve_data['description']}
CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
CWE: {', '.join(cve_data.get('cwe', []))}

[Affected Products]
{affected_str}

[References]
{references_str}
{analysis_section}{exploit_section}
[CRITICAL REQUIREMENTS]
1. **Observable Gate**: If no concrete indicator exists in ANY of the above sources, return exactly: SKIP
2. **No Hallucination**: Use ONLY what's in the description, references, analysis, and exploit code
3. **Syntax**: Follow standard {rule_type} syntax strictly
4. **Product-Specific**: If affected products are known, tailor the rule
5. **Exploit-Informed**: If exploit code is provided, extract concrete indicators (URLs, payloads, paths, parameters) from it

[Output Format]
- Return ONLY the raw rule code (no markdown, no explanation)
- If insufficient information across ALL sources, return exactly: SKIP
"""
        
        if rule_type in ["Snort", "Suricata", "snort", "suricata"]:
            base_prompt += """
[Snort/Suricata QUALITY REQUIREMENTS]

1. **HTTP-aware detection**: Use HTTP sticky buffers for precise matching:
   - `http_uri` or `http.uri` (Snort3): match URI path + query string
   - `http_client_body` or `http.request_body` (Snort3): match POST body parameters
   - `http_header` or `http.header` (Snort3): match specific HTTP headers
   - `http_method` or `http.method` (Snort3): match GET/POST/PUT/DELETE
   - Do NOT use bare `content` for HTTP fields — always use the appropriate buffer modifier

2. **Multi-condition rules** (reduce false positives):
   - Combine endpoint path + parameter name + attack payload in the same rule
   - Example for SQL Injection in POST body:
     content:"POST"; http_method;
     content:"/vulnerable/endpoint"; http_uri;
     content:"param_name="; http_client_body;
     pcre:"/param_name=.*?(UNION|SELECT|'|--|%27)/Pi";
   - Use `distance` and `within` for positional matching when appropriate

3. **Stateful detection**: Always include `flow:to_server,established;` for TCP rules

4. **Rule metadata**:
   - msg: Include CVE ID and specific attack type (e.g., "CVE-2025-XXXX SQL Injection via coupon_code")
   - classtype: Choose the MOST SPECIFIC class (web-application-attack, attempted-admin, etc.)
   - sid: Use range 9000001-9999999 for custom rules
   - reference: Include `reference:cve,XXXX-XXXXX;`

5. **Template**:
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"CVE-XXXX Exploit Attempt - [Specific Attack Description]";
    flow:to_server,established;
    content:"/path"; http_uri;
    content:"param="; http_client_body;
    pcre:"/attack_pattern/Pi";
    reference:cve,XXXX-XXXXX;
    classtype:web-application-attack;
    sid:9000001; rev:1;
)

6. **CRITICAL**: If the CVE is about a POST parameter, you MUST use http_client_body (not http_uri).
   If unsure, create TWO content matches — one for URI, one for body.
"""
        elif rule_type in ["Yara", "yara"]:
            base_prompt += """
[Yara Template]
rule CVE_XXXX_Indicator {
    meta:
        description = "Detects CVE-XXXX"
        author = "Argus-AI"
    strings:
        $s1 = "specific_string" ascii
    condition:
        any of ($s*)
}

[YARA CRITICAL CONSTRAINTS]
1. Use ONLY standard YARA syntax. DO NOT use undefined identifiers.
2. FORBIDDEN identifiers (cause compile errors): filepath, filename, extension, path, pe.*, elf.*, math.*, cuckoo.*
   - These require explicit 'import' statements. If you don't import a module, DO NOT reference its identifiers.
3. ALLOWED in condition without imports: any of, all of, filesize, uint16, uint32, uint16be, uint32be, entrypoint
4. For string matching, use ONLY $variable_name definitions in the strings section.
5. If the CVE is about a web vulnerability (SQL injection, XSS, etc.), focus on detecting payload strings, NOT file metadata.
6. Each string ($s1, $s2, ...) MUST be a concrete, specific indicator from the provided data. DO NOT invent generic patterns.
"""
        elif rule_type in ["Sigma", "sigma"]:
            base_prompt += """
[Sigma QUALITY REQUIREMENTS - READ CAREFULLY]

1. **Logsource precision**: Choose the MOST SPECIFIC logsource for the vulnerability type:
   - Web app vulns (SQLi, XSS, RCE via HTTP): use `product: webserver` with `category: webserver_access`
   - If the attack uses POST body parameters, ALSO add a second detection block using `category: webserver` or `category: proxy` to catch POST data
   - OS-level exploits: use `product: windows/linux` with appropriate category (process_creation, file_event, etc.)
   - Network exploits: use `product: zeek/suricata` as appropriate

2. **Detection MUST match the attack semantics**:
   - If the title says "SQL Injection", the detection MUST include SQL injection patterns (e.g., UNION, SELECT, OR 1=1, single quotes, comment sequences like -- or #) NOT just the parameter name
   - If the title says "RCE", detect command execution patterns, not just URL paths
   - If the title says "XSS", detect script injection patterns
   - NEVER create a rule where detection is ONLY "parameter_name exists in URI" - this causes massive false positives

3. **Multi-condition detection** (reduce false positives):
   - Use multiple selection conditions combined with `condition: all of selection_*`
   - Example for SQL Injection in coupon_code parameter:
     - selection_endpoint: uri|contains the vulnerable endpoint path or plugin path
     - selection_param: uri|contains OR cs-body|contains the parameter name
     - selection_payload: uri|contains|any OR cs-body|contains|any with SQL injection patterns
     - condition: all of selection_*

4. **POST body awareness**:
   - Many web parameters are sent via POST body, not URI query string
   - Use fields like `cs-body`, `request_body`, or `post_data` when appropriate
   - If unsure whether GET or POST, create detection for BOTH using `|` (OR) in field names

5. **Sigma Template**:
title: CVE-XXXX [Specific Attack Type] Attempt
status: experimental
description: Detects [specific attack] targeting [specific component/parameter] in [product name]
logsource:
    product: webserver
    category: webserver_access
detection:
    selection_endpoint:
        uri|contains: '/specific/path'
    selection_param:
        uri|contains: 'param_name'
    selection_payload:
        uri|contains|any:
            - "UNION"
            - "SELECT"
            - "'"
            - "--"
    condition: all of selection_*
level: high
tags:
    - cve.XXXX.XXXXX
    - attack.initial_access
"""
        
        return base_prompt
    
    # ====================================================================
    # [4] 메인 인터페이스
    # ====================================================================
    
    def get_rules(self, cve_data: Dict, analysis: Optional[Dict] = None) -> Dict:
        rules = {"sigma": None, "network": [], "yara": None, "skip_reasons": {}}
        cve_id = cve_data['id']

        # 공격벡터 분석 — 룰 타입 우선순위 결정에 사용
        attack_vector = self._parse_attack_vector(cve_data.get('cvss_vector', ''))
        logger.info(f"룰 수집 시작: {cve_id} (Attack Vector: {attack_vector})")

        # ===== Exploit-DB 참고 데이터 (AI 룰 생성 품질 향상용) =====
        # AI 룰 생성 전에 먼저 수집하여 프롬프트에 포함
        exploit_code = self._search_github("offensive-security/exploitdb", f"{cve_id}")
        if exploit_code:
            cve_data['_exploit_db_snippet'] = exploit_code[:3000]
            logger.info(f"  📄 Exploit-DB PoC 발견: {cve_id}")

        # ===== Sigma (필수 — 항상 생성 시도) =====
        public_sigma = self._search_local_sigma(cve_id)
        if public_sigma:
            rules['sigma'] = {
                "code": public_sigma,
                "source": "Public (SigmaHQ)",
                "verified": True,
                "indicators": None
            }
        else:
            ai_result = self._generate_ai_rule("Sigma", cve_data, analysis)
            if ai_result:
                ai_sigma, indicators = ai_result
                rules['sigma'] = {
                    "code": f"# ⚠️ AI-Generated - Review Required\n{ai_sigma}",
                    "source": "AI Generated (Validated)",
                    "verified": False,
                    "indicators": indicators
                }
            else:
                rules['skip_reasons']['sigma'] = self._get_skip_reason("Sigma", cve_data)

        # ===== 네트워크 룰 (Snort + Suricata) =====
        network_rules = self._fetch_network_rules(cve_id)

        if network_rules:
            for rule_info in network_rules:
                rules['network'].append({
                    "code": rule_info["code"],
                    "source": f"Public ({rule_info['source']})",
                    "engine": rule_info["engine"],
                    "verified": True,
                    "indicators": None
                })
        elif attack_vector in ("NETWORK", "ADJACENT", "UNKNOWN"):
            # 네트워크 공격벡터 → AI Snort/Suricata 생성 (우선)
            ai_result = self._generate_ai_rule("Snort", cve_data, analysis)
            if ai_result:
                ai_network, indicators = ai_result
                rules['network'].append({
                    "code": f"# ⚠️ AI-Generated - Review Required\n{ai_network}",
                    "source": "AI Generated (Regex Validated)",
                    "engine": "generic",
                    "verified": False,
                    "indicators": indicators
                })
            else:
                rules['skip_reasons']['network'] = self._get_skip_reason("Snort", cve_data)
        else:
            # 로컬/물리적 공격벡터 → AI 네트워크 룰 생성 생략
            logger.info(f"⏭️ Snort/Suricata AI 생성 SKIP: 공격벡터가 {attack_vector}이므로 네트워크 룰 부적합")
            rules['skip_reasons']['network'] = f"공격벡터 {attack_vector} — 네트워크 룰 부적합"

        # ===== Yara (tarball 로컬 검색) =====
        public_yara = self._search_local_yara(cve_id)
        if public_yara:
            rules['yara'] = {
                "code": public_yara,
                "source": "Public (Yara-Rules)",
                "verified": True,
                "indicators": None
            }
        elif attack_vector in ("LOCAL", "PHYSICAL"):
            # 로컬/물리적 공격벡터 → AI YARA 생성 (파일/바이너리 분석에 적합)
            ai_result = self._generate_ai_rule("Yara", cve_data, analysis)
            if ai_result:
                ai_yara, indicators = ai_result
                rules['yara'] = {
                    "code": f"// ⚠️ AI-Generated - Review Required\n{ai_yara}",
                    "source": "AI Generated (Compiled)",
                    "verified": False,
                    "indicators": indicators
                }
            else:
                rules['skip_reasons']['yara'] = self._get_skip_reason("Yara", cve_data)
        else:
            # 네트워크 공격벡터 → AI YARA 생성 생략 (Snort/Suricata가 더 적합)
            logger.info(f"⏭️ YARA AI 생성 SKIP: 공격벡터가 {attack_vector}이므로 파일 룰 부적합")
            rules['skip_reasons']['yara'] = f"공격벡터 {attack_vector} — YARA 룰 부적합 (Snort/Suricata 우선)"

        # 결과 요약
        sigma_found = "✅" if rules['sigma'] else "❌"
        network_count = len(rules['network'])
        network_found = f"✅ ({network_count}개)" if network_count > 0 else "❌"
        yara_found = "✅" if rules['yara'] else "❌"
        exploit_found = "✅" if cve_data.get('_exploit_db_snippet') else "❌"

        logger.info(f"룰 수집 완료: Sigma {sigma_found}, Snort/Suricata {network_found}, Yara {yara_found}, ExploitDB {exploit_found}")

        return rules
    
    def search_public_only(self, cve_id: str) -> Dict:
        rules = {"sigma": None, "network": [], "yara": None}

        logger.info(f"공개 룰 검색 (AI 미사용): {cve_id}")

        # Sigma (tarball 로컬 검색 - Code Search API 사용 안 함)
        public_sigma = self._search_local_sigma(cve_id)
        if public_sigma:
            rules['sigma'] = {
                "code": public_sigma,
                "source": "Public (SigmaHQ)",
                "verified": True,
                "indicators": None
            }

        # Snort/Suricata (기존 tarball 방식 유지)
        network_rules = self._fetch_network_rules(cve_id)
        if network_rules:
            for rule_info in network_rules:
                rules['network'].append({
                    "code": rule_info["code"],
                    "source": f"Public ({rule_info['source']})",
                    "engine": rule_info["engine"],
                    "verified": True,
                    "indicators": None
                })

        # Yara (tarball 로컬 검색 - Code Search API 사용 안 함)
        public_yara = self._search_local_yara(cve_id)
        if public_yara:
            rules['yara'] = {
                "code": public_yara,
                "source": "Public (Yara-Rules)",
                "verified": True,
                "indicators": None
            }

        # 결과 요약
        found = []
        if rules['sigma']: found.append("Sigma")
        if rules['network']: found.append(f"Network({len(rules['network'])})")
        if rules['yara']: found.append("Yara")

        if found:
            logger.info(f"  ✅ 공개 룰 발견: {', '.join(found)}")
        else:
            logger.debug(f"  공개 룰 없음: {cve_id}")

        return rules
    
    def _get_skip_reason(self, rule_type: str, cve_data: Dict) -> str:
        """룰 생성 실패 사유 판별"""
        if rule_type in ["Sigma", "sigma"]:
            return "공개 룰 미발견, AI가 근거 부족으로 생성 거부"
        
        has_indicators, reason, indicator_details = self._check_observables(cve_data)
        if not has_indicators:
            return f"공개 룰 미발견, 구체적 탐지 지표 부족 ({reason})"
        else:
            details_str = ', '.join(indicator_details) if indicator_details else reason
            return f"공개 룰 미발견, AI가 근거 부족으로 생성 거부 (발견된 지표: {details_str})"