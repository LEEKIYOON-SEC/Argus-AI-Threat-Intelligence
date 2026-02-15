import requests
import datetime
import pytz
import os
import re
import json
import time
from typing import List, Dict, Set, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from logger import logger
from rate_limiter import rate_limit_manager

class CollectorError(Exception):
    """데이터 수집 관련 에러"""
    pass

class Collector:
    """
    CVE 데이터 수집 전문 클래스 (v2.0)
    
    v2.0 변경사항:
    - 자체 _rate_limit_wait() 제거 → rate_limit_manager 통합 사용
    - 모든 API 호출에 check_and_wait() + record_call() 적용
    - 일관된 rate limit 관리
    """
    
    def __init__(self):
        self.kev_set: Set[str] = set()
        self.epss_cache: Dict[str, float] = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(requests.exceptions.RequestException)
    )
    def fetch_kev(self) -> bool:
        """CISA KEV 목록 다운로드"""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            rate_limit_manager.check_and_wait("kev")
            logger.info("Fetching CISA KEV list...")
            
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            rate_limit_manager.record_call("kev")
            
            data = response.json()
            self.kev_set = {vuln['cveID'] for vuln in data.get('vulnerabilities', [])}
            
            logger.info(f"Loaded {len(self.kev_set)} KEV entries")
            return True
            
        except requests.exceptions.Timeout:
            logger.error("KEV API timeout after 15s")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"KEV fetch failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in fetch_kev: {e}")
            return False
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_epss(self, cve_ids: List[str]) -> Dict[str, float]:
        """EPSS 점수 배치 수집"""
        if not cve_ids:
            return {}
        
        chunk_size = 50
        total_chunks = (len(cve_ids) + chunk_size - 1) // chunk_size
        
        logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs ({total_chunks} batches)")
        
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            chunk_num = (i // chunk_size) + 1
            
            try:
                rate_limit_manager.check_and_wait("epss")
                
                url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                rate_limit_manager.record_call("epss")
                
                for item in response.json().get('data', []):
                    cve_id = item.get('cve')
                    epss = float(item.get('epss', 0.0))
                    self.epss_cache[cve_id] = epss
                
                logger.debug(f"EPSS batch {chunk_num}/{total_chunks} complete")
                
            except Exception as e:
                logger.warning(f"EPSS batch {chunk_num} failed: {e}")
                continue
        
        return self.epss_cache
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_recent_cves(self, hours: int = 24) -> List[str]:
        """GitHub CVEProject에서 최근 CVE 수집"""
        now = datetime.datetime.now(pytz.UTC)
        since_str = (now - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?since={since_str}"
        
        try:
            rate_limit_manager.check_and_wait("github")
            logger.info(f"Fetching CVEs from last {hours} hours...")
            
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            rate_limit_manager.record_call("github")
            
            commits = response.json()
            cve_ids = set()
            
            for commit in commits:
                rate_limit_manager.check_and_wait("github")
                
                commit_response = requests.get(commit['url'], headers=self.headers, timeout=10)
                commit_response.raise_for_status()
                rate_limit_manager.record_call("github")
                
                for file in commit_response.json().get('files', []):
                    filename = file['filename']
                    
                    if filename.endswith(".json") and "CVE-" in filename:
                        match = re.search(r'(CVE-\d{4}-\d{4,7})', filename)
                        if match:
                            cve_ids.add(match.group(1))
            
            cve_list = list(cve_ids)
            logger.info(f"Found {len(cve_list)} unique CVEs")
            return cve_list
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in fetch_recent_cves: {e}")
            return []
    
    def parse_affected(self, affected_list: List[Dict]) -> List[Dict]:
        """Affected 정보 파싱"""
        results = []
        
        for item in affected_list:
            vendor = item.get('vendor', 'Unknown')
            product = item.get('product', 'Unknown')
            versions = []
            
            for v in item.get('versions', []):
                version = v.get('version', '')
                less_than = v.get('lessThan', '')
                less_than_eq = v.get('lessThanOrEqual', '')
                ver_str = ""
                
                if v.get('status') == "affected":
                    if version and version not in ["0", "n/a"]:
                        ver_str += f"{version} 부터 "
                    if less_than:
                        ver_str += f"{less_than} 이전"
                    elif less_than_eq:
                        ver_str += f"{less_than_eq} 이하"
                    elif not less_than and not less_than_eq and version:
                        ver_str = f"{version} (단일 버전)"
                    
                    if not ver_str:
                        ver_str = "모든 버전"
                    
                    versions.append(ver_str.strip())
            
            results.append({
                "vendor": vendor,
                "product": product,
                "versions": ", ".join(versions) if versions else "정보 없음"
            })
        
        return results
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5)
    )
    def enrich_cve(self, cve_id: str) -> Dict:
        """CVE 상세 정보 수집"""
        try:
            rate_limit_manager.check_and_wait("github")
            
            parts = cve_id.split('-')
            year, id_num = parts[1], parts[2]
            group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"
            
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            
            response = requests.get(raw_url, timeout=10)
            response.raise_for_status()
            rate_limit_manager.record_call("github")
            
            json_data = response.json()
            cna = json_data.get('containers', {}).get('cna', {})
            
            data = {
                "id": cve_id,
                "title": "N/A",
                "cvss": 0.0,
                "cvss_vector": "N/A",
                "description": "N/A",
                "state": "UNKNOWN",
                "cwe": [],
                "references": [],
                "affected": [],
                "cce": []
            }
            
            data['state'] = json_data.get('cveMetadata', {}).get('state', 'UNKNOWN')
            data['title'] = cna.get('title', 'N/A')
            data['affected'] = self.parse_affected(cna.get('affected', []))
            
            for desc in cna.get('descriptions', []):
                if desc.get('lang') == 'en':
                    data['description'] = desc.get('value', 'N/A')
                    break
            
            for metric in cna.get('metrics', []):
                if 'cvssV4_0' in metric:
                    data['cvss'] = metric['cvssV4_0'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV4_0'].get('vectorString', 'N/A')
                    break
                elif 'cvssV3_1' in metric:
                    data['cvss'] = metric['cvssV3_1'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV3_1'].get('vectorString', 'N/A')
                    break
                elif 'cvssV3_0' in metric:
                    data['cvss'] = metric['cvssV3_0'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV3_0'].get('vectorString', 'N/A')
                    break
            
            for pt in cna.get('problemTypes', []):
                for desc in pt.get('descriptions', []):
                    cwe_id = desc.get('cweId', desc.get('description', ''))
                    if cwe_id:
                        data['cwe'].append(cwe_id)
            
            for ref in cna.get('references', []):
                if 'url' in ref:
                    data['references'].append(ref['url'])
            
            json_str = json.dumps(json_data)
            cce_matches = re.findall(r'(CCE-\d{4,}-\d+)', json_str)
            if cce_matches:
                data['cce'] = list(set(cce_matches))
            
            logger.debug(f"Enriched {cve_id}: CVSS={data['cvss']}, State={data['state']}")
            return data
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"{cve_id} not found (404)")
            else:
                logger.error(f"{cve_id} HTTP error: {e}")
            return self._error_response(cve_id)
        except Exception as e:
            logger.error(f"{cve_id} enrichment failed: {e}")
            return self._error_response(cve_id)
    
    def _error_response(self, cve_id: str) -> Dict:
        """에러 발생 시 기본 응답"""
        return {
            "id": cve_id,
            "title": "Error",
            "cvss": 0.0,
            "cvss_vector": "N/A",
            "description": "Error",
            "state": "ERROR",
            "cwe": [],
            "references": [],
            "affected": [],
            "cce": []
        }
