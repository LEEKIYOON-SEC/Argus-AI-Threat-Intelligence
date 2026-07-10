import os
import io
import json
import re
import tarfile
import threading
import requests
import yaml
import yara
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Dict, Optional, Tuple, List
from logger import logger
from config import config
from rate_limiter import rate_limit_manager

# pySigma: Sigma 룰 실제 파싱 검증 (오프라인, 무료 pip) — 미설치 시 구조 검사만 수행
try:
    from sigma.collection import SigmaCollection
    _PYSIGMA_AVAILABLE = True
except ImportError:
    SigmaCollection = None
    _PYSIGMA_AVAILABLE = False

# suricataparser: Snort/Suricata 룰 실제 파싱 검증 (순수 Python) — 미설치 시 정규식 폴백
try:
    import suricataparser
    _SURICATAPARSER_AVAILABLE = True
except ImportError:
    suricataparser = None
    _SURICATAPARSER_AVAILABLE = False

class RuleManagerError(Exception):
    pass


# 디스크 캐시(24h TTL)·ExploitDB 인덱스는 enrichment_sources와 공유한다.
# (매시간 실행에서 재다운로드 방지 + collector와 동일 캐시 파일 재사용)
from enrichment_sources import (
    cache_get as _cache_get,
    cache_put as _cache_put,
    exploitdb_entry as _shared_exploitdb_entry,
    EXPLOITDB_RAW_BASE as _EXPLOITDB_RAW_BASE_SHARED,
)


class RuleManager:
    # 룰셋/인덱스 캐시 (클래스 수준 - 모든 인스턴스·워커 공유)
    _sigma_files: Dict[str, str] = {}
    _yara_files: Dict[str, str] = {}
    _network_rules_cache: Dict[str, str] = {}
    # nuclei-templates CVE 인덱스: CVE-ID → 템플릿 파일 경로
    _nuclei_index: Dict[str, str] = {}
    _nuclei_index_loaded = False
    # 병렬 워커 간 중복 다운로드 방지
    _download_lock = threading.Lock()

    _NUCLEI_RAW_BASE = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/"
    _EXPLOITDB_RAW_BASE = _EXPLOITDB_RAW_BASE_SHARED

    # 공식 룰 재게시 시 보존해야 할 출처·라이선스 고지 (불변 원칙 8-①)
    _SOURCE_LICENSES = [
        ("SigmaHQ", "DRL 1.1 — 재게시 시 author 표기 보존 의무"),
        ("ET Open", "MIT — 레거시 SID 1–3464는 GPLv2 (헤더 고지 보존)"),
        ("Community", "GPLv2 (Snort Community Rules)"),
        ("Yara-Rules", "GPL-2.0 — 출처·라이선스 표기 유지"),
    ]

    @staticmethod
    def _license_for_source(source: str) -> Optional[str]:
        """룰 출처 문자열에서 라이선스 고지 문구를 찾는다"""
        for key, lic in RuleManager._SOURCE_LICENSES:
            if key.lower() in source.lower():
                return lic
        return None

    def __init__(self):
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1

        sigma_mode = "pySigma" if _PYSIGMA_AVAILABLE else "구조 검사"
        net_mode = "suricataparser" if _SURICATAPARSER_AVAILABLE else "정규식"
        logger.info(f"✅ RuleManager 초기화 완료 (Sigma: {sigma_mode}, Network: {net_mode}, Yara: 컴파일)")

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

    def _fetch_network_rules(self, cve_id: str) -> List[Dict[str, str]]:
        logger.debug(f"네트워크 룰셋 검색 시작: {cve_id}")

        found_rules = []

        # 캐시가 비어있으면 룰셋 다운로드 (첫 실행 시)
        if not RuleManager._network_rules_cache:
            self._download_all_rulesets()

        # 각 룰셋에서 CVE 검색
        for ruleset_name, ruleset_content in RuleManager._network_rules_cache.items():
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
        with RuleManager._download_lock:
            if RuleManager._network_rules_cache:
                return

            logger.info("📥 네트워크 룰셋 로드 중...")

            # (이름, URL, tarball 내 추출 대상 파일명 — None이면 plain text)
            sources = [
                ("Snort 2.9 Community", "https://www.snort.org/downloads/community/community-rules.tar.gz", "community.rules"),
                ("Snort 3 Community", "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz", "snort3-community.rules"),
                ("Snort 2.9 ET Open", "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules", None),
                ("Suricata 5 ET Open", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules", None),
                ("Suricata 7 ET Open", "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules", None),
            ]

            for name, url, member_hint in sources:
                cache_key = re.sub(r'[^a-z0-9]+', '-', name.lower()).strip('-') + ".rules"

                cached = _cache_get(cache_key)
                if cached is not None:
                    RuleManager._network_rules_cache[name] = cached.decode('utf-8', errors='ignore')
                    logger.info(f"  ✅ {name} 캐시 로드")
                    continue

                try:
                    logger.debug(f"  - {name} 다운로드 중...")
                    response = requests.get(url, timeout=60)
                    if response.status_code != 200:
                        logger.debug(f"  ⚠️ {name} 다운로드 실패: HTTP {response.status_code}")
                        continue

                    if member_hint:
                        content = None
                        with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                            for member in tar.getmembers():
                                if member_hint in member.name:
                                    f = tar.extractfile(member)
                                    if f:
                                        content = f.read().decode('utf-8', errors='ignore')
                                    break
                        if content is None:
                            logger.debug(f"  ⚠️ {name}: tarball에서 {member_hint} 미발견")
                            continue
                    else:
                        content = response.text

                    RuleManager._network_rules_cache[name] = content
                    _cache_put(cache_key, content.encode('utf-8'))
                    logger.info(f"  ✅ {name} 로드 완료")
                except Exception as e:
                    logger.warning(f"  ⚠️ {name} 다운로드 실패: {e}")

            logger.info(f"✅ 네트워크 룰셋 로드 완료 ({len(RuleManager._network_rules_cache)}개 소스)")
    
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

    def _fetch_tarball(self, cache_key: str, url: str, display_name: str) -> Optional[bytes]:
        """tarball을 디스크 캐시 우선으로 가져온다 (miss 시 다운로드 후 캐시)"""
        data = _cache_get(cache_key)
        if data is not None:
            logger.info(f"📥 {display_name} 캐시 로드")
            return data

        logger.info(f"📥 {display_name} 다운로드 중...")
        headers = {"Authorization": f"token {self.gh_token}"} if self.gh_token else {}
        try:
            rate_limit_manager.check_and_wait("ruleset_download")
            response = requests.get(url, headers=headers, timeout=60)
            response.raise_for_status()
            rate_limit_manager.record_call("ruleset_download")
            _cache_put(cache_key, response.content)
            return response.content
        except Exception as e:
            logger.warning(f"  ⚠️ {display_name} 다운로드 실패: {e}")
            return None

    def _download_sigma_repo(self):
        """SigmaHQ/sigma tarball(디스크 캐시)에서 rules/*.yml 파일 캐시"""
        with RuleManager._download_lock:
            if RuleManager._sigma_files:
                return

            data = self._fetch_tarball("sigmahq.tar.gz", "https://api.github.com/repos/SigmaHQ/sigma/tarball", "SigmaHQ 룰셋")
            if data is None:
                return

            try:
                count = 0
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member.isfile() and member.name.endswith('.yml') and '/rules' in member.name:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode('utf-8', errors='ignore')
                                RuleManager._sigma_files[member.name] = content
                                count += 1

                logger.info(f"  ✅ SigmaHQ 로드 완료 ({count}개 룰)")
            except Exception as e:
                logger.warning(f"  ⚠️ SigmaHQ 압축 해제 실패: {e}")

    def _download_yara_repo(self):
        """Yara-Rules/rules tarball(디스크 캐시)에서 *.yar 파일 캐시"""
        with RuleManager._download_lock:
            if RuleManager._yara_files:
                return

            data = self._fetch_tarball("yara-rules.tar.gz", "https://api.github.com/repos/Yara-Rules/rules/tarball", "Yara-Rules 룰셋")
            if data is None:
                return

            try:
                count = 0
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if member.isfile() and (member.name.endswith('.yar') or member.name.endswith('.yara')):
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode('utf-8', errors='ignore')
                                RuleManager._yara_files[member.name] = content
                                count += 1

                logger.info(f"  ✅ Yara-Rules 로드 완료 ({count}개 룰)")
            except Exception as e:
                logger.warning(f"  ⚠️ Yara-Rules 압축 해제 실패: {e}")

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

    def _load_nuclei_index(self):
        """nuclei-templates의 CVE 인덱스(cves.json, ~2MB)만 로드.

        전체 tarball(수백MB) 대신 인덱스로 CVE→템플릿 경로를 매핑하고,
        해당 CVE의 템플릿 파일 하나만 raw로 조회한다 (불변 원칙 4 — 컨텍스트 유지, 수집 비용만 절감).
        """
        with RuleManager._download_lock:
            if RuleManager._nuclei_index_loaded:
                return
            RuleManager._nuclei_index_loaded = True

            raw = _cache_get("nuclei-cve-index.jsonl")
            if raw is None:
                logger.info("📥 nuclei CVE 인덱스 다운로드 중...")
                try:
                    rate_limit_manager.check_and_wait("ruleset_download")
                    response = requests.get(RuleManager._NUCLEI_RAW_BASE + "cves.json", timeout=30)
                    response.raise_for_status()
                    rate_limit_manager.record_call("ruleset_download")
                    raw = response.content
                    _cache_put("nuclei-cve-index.jsonl", raw)
                except Exception as e:
                    logger.warning(f"  ⚠️ nuclei CVE 인덱스 다운로드 실패: {e}")
                    return
            else:
                logger.info("📥 nuclei CVE 인덱스 캐시 로드")

            for line in raw.decode('utf-8', errors='ignore').splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                entry_id = str(entry.get("ID", "")).upper()
                file_path = entry.get("file_path", "")
                if entry_id.startswith("CVE-") and file_path:
                    RuleManager._nuclei_index[entry_id] = file_path

            logger.info(f"  ✅ nuclei CVE 인덱스 로드 완료 ({len(RuleManager._nuclei_index)}개 CVE)")

    def _search_nuclei(self, cve_id: str) -> Optional[str]:
        """nuclei CVE 인덱스 조회 후 해당 템플릿 파일 하나만 raw로 가져온다"""
        self._load_nuclei_index()

        file_path = RuleManager._nuclei_index.get(cve_id.upper())
        if not file_path:
            logger.debug(f"❌ nuclei-templates: {cve_id} 없음")
            return None

        try:
            response = requests.get(RuleManager._NUCLEI_RAW_BASE + file_path, timeout=15)
            response.raise_for_status()
            logger.info(f"✅ nuclei-templates에서 발견: {file_path.split('/')[-1]}")
            return response.text
        except Exception as e:
            logger.warning(f"⚠️ nuclei 템플릿 조회 실패 ({cve_id}): {e}")
            return None

    # ====================================================================
    # [1-3] Exploit-DB CSV 매핑 (Code Search API 대체 — 인덱스는 enrichment_sources 공유)
    # ====================================================================

    def _search_exploitdb(self, cve_id: str) -> Optional[Dict[str, str]]:
        """Exploit-DB 인덱스(enrichment_sources 공유) 조회 후 exploit 파일 원문을 가져온다.

        반환: {"code": <원문>, "url": <exploit-db.com 링크>, "edb_id": <ID>}
        원문(code)은 AI 프롬프트 컨텍스트 전용, url만 Issue/대시보드에 게시 (불변 원칙 8-②).
        """
        mapping = _shared_exploitdb_entry(cve_id)
        if not mapping:
            logger.debug(f"❌ Exploit-DB: {cve_id} 없음")
            return None

        file_path, edb_id = mapping
        edb_url = f"https://www.exploit-db.com/exploits/{edb_id}" if edb_id else None
        try:
            response = requests.get(RuleManager._EXPLOITDB_RAW_BASE + file_path, timeout=15)
            response.raise_for_status()
            logger.info(f"✅ Exploit-DB PoC 발견: EDB-{edb_id} ({file_path.split('/')[-1]})")
            return {"code": response.text, "url": edb_url, "edb_id": edb_id}
        except Exception as e:
            logger.warning(f"⚠️ Exploit-DB 파일 조회 실패 ({cve_id}): {e}")
            # 파일 조회 실패해도 링크는 유효하므로 반환
            return {"code": "", "url": edb_url, "edb_id": edb_id} if edb_url else None

    # ====================================================================
    # [2] 룰 검증 (정규식 기반)
    # ====================================================================

    def _validate_sigma(self, code: str) -> bool:
        """
        Sigma 룰 검증 (강화)

        구조 검사(사전 필터) + pySigma 실제 파싱(최종 게이트):
        1. YAML 파싱
        2. 필수 필드 존재 (title, logsource, detection)
        3. logsource에 product 또는 category
        4. detection에 condition 필드
        5. detection에 최소 1개 selection 존재
        6. selection이 단순 파라미터만이 아닌지 (semantic check)
        7. level 필드 존재 및 유효값 (critical/high/medium/low/informational)
        8. pySigma SigmaCollection.from_yaml 파싱 — 필드 modifier·condition 참조까지 실검증
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

            # level 필드 검사
            level = data.get('level')
            valid_levels = {'critical', 'high', 'medium', 'low', 'informational'}
            if not level or str(level).lower() not in valid_levels:
                logger.warning(f"Sigma: level 필드 누락 또는 유효하지 않음 - {level!r}")
                return False

            # 최종 게이트: pySigma 실제 파싱 (modifier 유효성 + condition 참조 해석)
            if _PYSIGMA_AVAILABLE:
                try:
                    collection = SigmaCollection.from_yaml(code)
                    for parsed_rule in collection.rules:
                        # condition은 지연 파싱이므로 명시적으로 해석 강제
                        # → 존재하지 않는 selection 참조(AI 환각) 검출
                        for cond in parsed_rule.detection.parsed_condition:
                            cond.parse()
                except Exception as e:
                    logger.warning(f"Sigma: pySigma 파싱 실패 - {e}")
                    return False
            else:
                logger.debug("pySigma 미설치 — 구조 검사까지만 수행")

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
        네트워크 룰 검증 (Snort/Suricata)

        suricataparser(순수 Python 룰 파서)로 실제 파싱하는 것이 1차 게이트.
        미설치 환경에서는 기존 정규식 휴리스틱으로 폴백.

        Args:
            code: Snort 또는 Suricata 룰 문자열

        Returns:
            검증 통과 여부
        """
        code = code.strip()

        if _SURICATAPARSER_AVAILABLE:
            # AI가 여러 줄로 포매팅한 룰을 단일 라인으로 정규화 (파서는 한 줄 룰 기준)
            normalized = re.sub(r'\s*\n\s*', ' ', code)
            try:
                rule = suricataparser.parse_rule(normalized)
            except Exception as e:
                logger.warning(f"네트워크 룰: 파싱 실패 - {e}")
                return False

            if rule is None:
                logger.warning("네트워크 룰: suricataparser 파싱 불가 (구조 오류)")
                return False
            if not getattr(rule, 'sid', None):
                logger.warning("네트워크 룰: sid 옵션 누락")
                return False
            if not getattr(rule, 'msg', None):
                logger.warning("네트워크 룰: msg 옵션 누락")
                return False

            logger.debug("✅ 네트워크 룰 파서 검증 통과 (suricataparser)")
            return True

        return self._validate_network_rule_regex(code)

    def _validate_network_rule_regex(self, code: str) -> bool:
        """
        네트워크 룰 검증 폴백 (정규식 기반 — suricataparser 미설치 환경 전용)

        6단계 검증 과정:
        1. 기본 구조 (alert tcp ...)
        2. 필수 요소 (변수, 포트, 방향)
        3. msg 필드 (필수)
        4. sid 필드 (필수)
        5. 일반적인 문법 오류 (빈 괄호, 연속 세미콜론 등)
        6. 괄호 균형
        """
        
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
    
    def _self_check_rule(self, rule_type: str, rule_code: str, cve_data: Dict) -> Tuple[str, str]:
        """AI 생성 룰 자기검증 (저비용 1회, non-thinking 모드로 토큰 절감)

        생성된 룰이 CVE 설명과 실제로 일치하는지, 명백한 FP 위험은 없는지 검토.
        TPD 게이트 뒤에 배치되어 토큰 예산 안전.

        Returns:
            ("PASS" | "FAIL" | "SKIP", 사유)
            - PASS: 일치 확인 → trust: ai-validated
            - FAIL: 불일치 → 룰 폐기, skip_reasons에 사유 기록
            - SKIP: 검증 수행 불가(TPD 부족 등) → trust: ai-draft로 유지
        """
        if rate_limit_manager.is_tpd_exhausted("groq", required_tokens=3000):
            return "SKIP", "Groq TPD 부족으로 자기검증 생략"

        prompt = f"""You are a detection engineering reviewer. Review this {rule_type} rule generated for {cve_data['id']}.

[CVE Description]
{cve_data['description'][:1500]}

[Generated Rule]
{rule_code[:2500]}

Check strictly:
1. Does the detection logic actually match the vulnerability described (attack vector, component, parameter, payload)?
2. Is there an obvious false-positive risk (e.g., detection is only a generic keyword, a bare parameter name, or unrelated patterns)?

Respond in EXACTLY this format (no other text):
VERDICT: PASS or FAIL
REASON: <one short sentence>"""

        try:
            rate_limit_manager.check_and_wait("groq")
            # 단순 PASS/FAIL 판정 → non-thinking으로 빠르고 저렴하게 (TPD 절감)
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.0,
                max_completion_tokens=512,
                reasoning_effort="none",
                reasoning_format="parsed"
            )
            tokens_used = 0
            if hasattr(response, 'usage') and response.usage:
                tokens_used = response.usage.total_tokens
            rate_limit_manager.record_call("groq", tokens_used=tokens_used)

            text = (response.choices[0].message.content or "").strip()
            reason_match = re.search(r'REASON:\s*(.+)', text)
            reason = reason_match.group(1).strip() if reason_match else text[:200]

            if re.search(r'VERDICT:\s*PASS', text, re.IGNORECASE):
                return "PASS", reason
            if re.search(r'VERDICT:\s*FAIL', text, re.IGNORECASE):
                return "FAIL", reason
            return "SKIP", f"자기검증 응답 형식 불명확: {text[:120]}"

        except Exception as e:
            logger.warning(f"자기검증 호출 실패 ({rule_type}): {e}")
            return "SKIP", f"자기검증 호출 실패: {e}"

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _generate_ai_rule(self, rule_type: str, cve_data: Dict, analysis: Optional[Dict] = None) -> Optional[Tuple[str, List[str], str]]:
        """
        AI 기반 탐지 룰 생성

        공개 룰이 없고, 구체적 지표가 충분할 때만 AI에게 룰을 생성하도록 요청.
        생성 후 구문 검증 → 자기검증 패스를 거쳐 trust 등급을 부여한다.

        Returns:
            (룰 코드, 발견된 지표 목록, trust: "ai-validated"|"ai-draft") 또는 None
        """
        logger.debug(f"AI {rule_type} 생성 시도")
        # 실패/생략 시 구체적 사유 (skip_reasons 고도화용)
        self._last_skip_detail = None

        # Observable Gate (Sigma는 예외 - 로그 기반이라 관대하게)
        indicator_details = []
        if rule_type not in ["Sigma", "sigma"]:
            has_indicators, reason, indicator_details = self._check_observables(cve_data)
            if not has_indicators:
                logger.info(f"⛔ {rule_type} 생성 SKIP: {reason}")
                self._last_skip_detail = f"구체적 탐지 지표 부족 ({reason})"
                return None
            else:
                logger.debug(f"✅ Observable Gate 통과: {reason}")

        prompt = self._build_rule_prompt(rule_type, cve_data, analysis)

        try:
            # TPD 소진 시 룰 생성 SKIP
            if rate_limit_manager.is_tpd_exhausted("groq"):
                logger.warning(f"⛔ {rule_type} 생성 SKIP: Groq TPD 소진")
                self._last_skip_detail = "Groq TPD 소진으로 AI 생성 생략 (다음 실행에서 재처리)"
                return None

            rate_limit_manager.check_and_wait("groq")
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_RULE_PARAMS["temperature"],
                top_p=config.GROQ_RULE_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_RULE_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_RULE_PARAMS["reasoning_effort"],
                reasoning_format=config.GROQ_RULE_PARAMS["reasoning_format"]
            )
            # 토큰 사용량 기록 (TPD 트래킹)
            tokens_used = 0
            if hasattr(response, 'usage') and response.usage:
                tokens_used = response.usage.total_tokens
            rate_limit_manager.record_call("groq", tokens_used=tokens_used)

            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip()

            if content == "SKIP" or not content:
                # Sigma는 필수 생성 — SKIP 시 관대한 프롬프트로 1회 재시도
                if rule_type in ["Sigma", "sigma"] and not getattr(self, '_sigma_retry_done', False):
                    self._sigma_retry_done = True
                    logger.info(f"⚠️ Sigma SKIP → 필수 생성이므로 관대한 프롬프트로 재시도")

                    # TPD 소진 시 재시도도 SKIP
                    if rate_limit_manager.is_tpd_exhausted("groq"):
                        logger.warning(f"⛔ Sigma 재시도 SKIP: Groq TPD 소진")
                        self._sigma_retry_done = False
                        self._last_skip_detail = "Groq TPD 소진으로 Sigma 재시도 생략"
                        return None

                    retry_prompt = self._build_rule_prompt(rule_type, cve_data, analysis)
                    retry_prompt += "\n\n[OVERRIDE] Sigma is MANDATORY. Generate a best-effort Sigma rule using whatever information is available. Do NOT return SKIP."
                    rate_limit_manager.check_and_wait("groq")
                    retry_resp = self.groq_client.chat.completions.create(
                        model=self.model,
                        messages=[{"role": "user", "content": retry_prompt}],
                        temperature=config.GROQ_RULE_PARAMS["temperature"],
                        top_p=config.GROQ_RULE_PARAMS["top_p"],
                        max_completion_tokens=config.GROQ_RULE_PARAMS["max_completion_tokens"],
                        reasoning_effort=config.GROQ_RULE_PARAMS["reasoning_effort"],
                        reasoning_format=config.GROQ_RULE_PARAMS["reasoning_format"]
                    )
                    retry_tokens = 0
                    if hasattr(retry_resp, 'usage') and retry_resp.usage:
                        retry_tokens = retry_resp.usage.total_tokens
                    rate_limit_manager.record_call("groq", tokens_used=retry_tokens)
                    retry_content = retry_resp.choices[0].message.content.strip()
                    retry_content = re.sub(r"```[a-z]*\n|```", "", retry_content).strip()
                    if retry_content and retry_content != "SKIP" and self._validate_sigma(retry_content):
                        self._sigma_retry_done = False
                        # 재시도 룰도 자기검증 패스 적용
                        verdict, check_reason = self._self_check_rule(rule_type, retry_content, cve_data)
                        if verdict == "FAIL":
                            logger.warning(f"🗑️ Sigma 필수 재시도 룰 자기검증 불일치로 폐기: {check_reason}")
                            self._last_skip_detail = f"AI 자기검증 불일치로 폐기 ({check_reason})"
                            return None
                        trust = "ai-validated" if verdict == "PASS" else "ai-draft"
                        logger.info(f"✅ Sigma 필수 재시도 성공 ({trust})")
                        return (retry_content, indicator_details, trust)
                    self._sigma_retry_done = False
                    self._last_skip_detail = "Sigma 필수 재시도도 실패 (SKIP 재반환 또는 구문/의미 검증 불통과)"
                    logger.info(f"⛔ AI가 {rule_type} 생성 거부 (근거 부족)")
                    return None
                logger.info(f"⛔ AI가 {rule_type} 생성 거부 (근거 부족)")
                found = ', '.join(indicator_details) if indicator_details else "없음"
                self._last_skip_detail = f"AI가 근거 부족으로 생성 거부(SKIP 반환) — 제공 지표: {found}"
                return None

            # 검증 (구문/의미)
            is_valid = False
            if rule_type in ["Snort", "Suricata", "snort", "suricata"]:
                is_valid = self._validate_network_rule(content)
            elif rule_type in ["Yara", "yara"]:
                is_valid = self._validate_yara(content)
            elif rule_type in ["Sigma", "sigma"]:
                is_valid = self._validate_sigma(content)

            if not is_valid:
                logger.warning(f"❌ AI {rule_type} 검증 실패")
                logger.debug(f"실패한 룰:\n{content}")
                self._last_skip_detail = f"AI 생성 룰이 {rule_type} 구문/의미 검증에 실패해 폐기"
                return None

            # 자기검증 패스: 룰이 CVE 설명과 일치하는가, FP 위험은? (불일치 시 폐기)
            verdict, check_reason = self._self_check_rule(rule_type, content, cve_data)
            if verdict == "FAIL":
                logger.warning(f"🗑️ AI {rule_type} 자기검증 불일치로 폐기: {check_reason}")
                self._last_skip_detail = f"AI 자기검증 불일치로 폐기 ({check_reason})"
                return None

            trust = "ai-validated" if verdict == "PASS" else "ai-draft"
            if verdict == "PASS":
                logger.info(f"✅ AI {rule_type} 생성·검증·자기검증 통과 (ai-validated)")
            else:
                logger.info(f"✅ AI {rule_type} 생성 및 검증 성공 — 자기검증 생략 → ai-draft ({check_reason})")
            return (content, indicator_details, trust)

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

        # Nuclei 템플릿 참고
        nuclei_section = ""
        if cve_data.get('_nuclei_template'):
            nuclei_section = f"""
[Nuclei Template (Community Detection)]
Existing detection template. Extract concrete indicators:
{cve_data['_nuclei_template']}
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
{analysis_section}{nuclei_section}{exploit_section}
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
     - selection_payload: uri|contains OR cs-body|contains with a LIST of SQL injection patterns (list values are OR-ed by default; do NOT invent modifiers like |any)
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
        uri|contains:
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

        # ===== Nuclei-templates 참고 데이터 (AI 룰 생성 품질 향상용) =====
        nuclei_template = self._search_nuclei(cve_id)
        if nuclei_template:
            cve_data['_nuclei_template'] = nuclei_template[:3000]
            logger.info(f"  📄 Nuclei 템플릿 발견: {cve_id}")

        # ===== Exploit-DB 참고 데이터 (AI 룰 생성 품질 향상용) =====
        # AI 룰 생성 전에 먼저 수집하여 프롬프트에 포함.
        # PoC 원문은 프롬프트 컨텍스트 전용, Issue/대시보드에는 링크(_exploit_db_url)만 게시 (불변 원칙 8-②)
        exploit_info = self._search_exploitdb(cve_id)
        if exploit_info:
            if exploit_info.get("code"):
                cve_data['_exploit_db_snippet'] = exploit_info["code"][:3000]
            if exploit_info.get("url"):
                cve_data['_exploit_db_url'] = exploit_info["url"]
            logger.info(f"  📄 Exploit-DB PoC 발견: {cve_id}")

        # ===== Sigma (필수 — 항상 생성 시도) =====
        public_sigma = self._search_local_sigma(cve_id)
        if public_sigma:
            rules['sigma'] = {
                "code": public_sigma,
                "source": "Public (SigmaHQ)",
                "verified": True,
                "indicators": None,
                "trust": "official-verified",
                "license": self._license_for_source("SigmaHQ")
            }
        else:
            ai_result = self._generate_ai_rule("Sigma", cve_data, analysis)
            if ai_result:
                ai_sigma, indicators, trust = ai_result
                rules['sigma'] = {
                    "code": f"# ⚠️ AI-Generated - Review Required\n{ai_sigma}",
                    "source": "AI Generated (Validated)",
                    "verified": False,
                    "indicators": indicators,
                    "trust": trust
                }
            else:
                rules['skip_reasons']['sigma'] = self._get_skip_reason("Sigma", cve_data)

        # ===== 네트워크 룰 (Snort + Suricata) =====
        network_rules = self._fetch_network_rules(cve_id)

        if network_rules:
            for rule_info in network_rules:
                source_str = f"Public ({rule_info['source']})"
                rules['network'].append({
                    "code": rule_info["code"],
                    "source": source_str,
                    "engine": rule_info["engine"],
                    "verified": True,
                    "indicators": None,
                    "trust": "official-verified",
                    "license": self._license_for_source(source_str)
                })
        elif attack_vector in ("NETWORK", "ADJACENT", "UNKNOWN"):
            # 네트워크 공격벡터 → AI Snort/Suricata 생성 (우선)
            ai_result = self._generate_ai_rule("Snort", cve_data, analysis)
            if ai_result:
                ai_network, indicators, trust = ai_result
                rules['network'].append({
                    "code": f"# ⚠️ AI-Generated - Review Required\n{ai_network}",
                    "source": "AI Generated (Parser Validated)",
                    "engine": "generic",
                    "verified": False,
                    "indicators": indicators,
                    "trust": trust
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
                "indicators": None,
                "trust": "official-verified",
                "license": self._license_for_source("Yara-Rules")
            }
        elif attack_vector in ("LOCAL", "PHYSICAL"):
            # 로컬/물리적 공격벡터 → AI YARA 생성 (파일/바이너리 분석에 적합)
            ai_result = self._generate_ai_rule("Yara", cve_data, analysis)
            if ai_result:
                ai_yara, indicators, trust = ai_result
                rules['yara'] = {
                    "code": f"// ⚠️ AI-Generated - Review Required\n{ai_yara}",
                    "source": "AI Generated (Compiled)",
                    "verified": False,
                    "indicators": indicators,
                    "trust": trust
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
        rules = {"sigma": None, "network": [], "yara": None, "skip_reasons": {}}

        logger.info(f"공개 룰 검색 (AI 미사용): {cve_id}")

        # Sigma (tarball 로컬 검색 - Code Search API 사용 안 함)
        public_sigma = self._search_local_sigma(cve_id)
        if public_sigma:
            rules['sigma'] = {
                "code": public_sigma,
                "source": "Public (SigmaHQ)",
                "verified": True,
                "indicators": None,
                "trust": "official-verified",
                "license": self._license_for_source("SigmaHQ")
            }

        # Snort/Suricata (기존 tarball 방식 유지)
        network_rules = self._fetch_network_rules(cve_id)
        if network_rules:
            for rule_info in network_rules:
                source_str = f"Public ({rule_info['source']})"
                rules['network'].append({
                    "code": rule_info["code"],
                    "source": source_str,
                    "engine": rule_info["engine"],
                    "verified": True,
                    "indicators": None,
                    "trust": "official-verified",
                    "license": self._license_for_source(source_str)
                })

        # Yara (tarball 로컬 검색 - Code Search API 사용 안 함)
        public_yara = self._search_local_yara(cve_id)
        if public_yara:
            rules['yara'] = {
                "code": public_yara,
                "source": "Public (Yara-Rules)",
                "verified": True,
                "indicators": None,
                "trust": "official-verified",
                "license": self._license_for_source("Yara-Rules")
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
        """룰 생성 실패 사유 판별 — 확인한 공개 저장소·컨텍스트 소스·부족 지표를 구체적으로 명시"""
        repo_map = {
            "sigma": "SigmaHQ",
            "snort": "ET Open/Snort Community",
            "suricata": "ET Open/Snort Community",
            "yara": "Yara-Rules",
        }
        searched_repo = repo_map.get(rule_type.lower(), "공개 저장소")

        # AI 프롬프트에 어떤 컨텍스트 소스가 들어갔는지
        sources = [
            f"nuclei {'✅' if cve_data.get('_nuclei_template') else '❌'}",
            f"ExploitDB {'✅' if cve_data.get('_exploit_db_snippet') else '❌'}",
            "description ✅",
        ]
        sources_str = ", ".join(sources)

        # 직전 AI 생성 시도가 남긴 구체적 사유 (TPD 생략/검증 실패/자기검증 폐기 등)
        detail = getattr(self, '_last_skip_detail', None)
        if not detail:
            has_indicators, obs_reason, indicator_details = self._check_observables(cve_data)
            if rule_type in ["Sigma", "sigma"]:
                detail = "AI가 근거 부족으로 생성 거부"
            elif not has_indicators:
                detail = f"구체적 탐지 지표 부족 ({obs_reason})"
            else:
                found = ', '.join(indicator_details) if indicator_details else obs_reason
                detail = f"AI가 근거 부족으로 생성 거부 (발견된 지표: {found})"

        return f"공개 룰 미발견({searched_repo}); {detail}; 확인한 컨텍스트: [{sources_str}]"