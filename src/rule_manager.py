import os
import io
import json
import re
import tarfile
import threading
import requests
from typing import Dict, Optional, List
from logger import logger
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


# 디스크 캐시(24h TTL)는 enrichment_sources와 공유한다.
# (매시간 실행에서 재다운로드 방지 + collector와 동일 캐시 파일 재사용)
from enrichment_sources import (
    cache_get as _cache_get,
    cache_put as _cache_put,
)


class RuleManager:
    # 룰셋 캐시 (클래스 수준 - 모든 인스턴스·워커 공유)
    _sigma_files: Dict[str, str] = {}
    _yara_files: Dict[str, str] = {}
    _network_rules_cache: Dict[str, str] = {}
    # 병렬 워커 간 중복 다운로드 방지
    _download_lock = threading.Lock()

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
        # AI 룰 생성 제거 — RuleManager는 공개 룰 검색 전용 (Groq 미사용)
        logger.info("✅ RuleManager 초기화 완료 (공개 룰 검색 전용: SigmaHQ / ET Open / Yara-Rules)")

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
    