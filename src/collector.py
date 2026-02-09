import requests
import datetime
import pytz
import os
import re

class Collector:
    def __init__(self):
        self.kev_set = set()
        self.epss_cache = {}
        # GitHub API 호출을 위해 토큰 사용 (Rate Limit 방지)
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }

    def fetch_kev(self):
        """CISA KEV 카탈로그 로드"""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                data = res.json()
                self.kev_set = {vuln['cveID'] for vuln in data['vulnerabilities']}
                print(f"[INFO] Loaded {len(self.kev_set)} KEVs")
        except Exception as e:
            print(f"[WARN] Failed to fetch KEV: {e}")

    def fetch_epss(self, cve_ids):
        """First.org에서 EPSS 일괄 조회"""
        if not cve_ids: return
        
        # 50개씩 끊어서 조회
        chunk_size = 50
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            ids_str = ",".join(chunk)
            url = f"https://api.first.org/data/v1/epss?cve={ids_str}"
            try:
                res = requests.get(url, timeout=10)
                if res.status_code == 200:
                    data = res.json().get('data', [])
                    for item in data:
                        self.epss_cache[item['cve']] = float(item['epss'])
            except Exception as e:
                print(f"[WARN] EPSS fetch failed: {e}")

    def fetch_recent_cves(self, hours=2):
        """
        [Final Solution] CVEProject/cvelistV5 리포지토리의 커밋 내역을 조회합니다.
        가장 확실하고 빠르며, 인증 오류가 없습니다.
        """
        now = datetime.datetime.now(pytz.UTC)
        since_time = now - datetime.timedelta(hours=hours)
        since_str = since_time.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # CVE 공식 데이터 저장소 (cvelistV5)의 커밋 조회
        url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?since={since_str}"
        
        print(f"\n[DEBUG] Tracking Changes from: {url}")

        try:
            res = requests.get(url, headers=self.headers, timeout=10)
            
            if res.status_code == 200:
                commits = res.json()
                print(f"[DEBUG] Found {len(commits)} commits in last {hours} hours")
                
                cve_ids = set()
                
                # 각 커밋마다 변경된 파일 확인
                for commit in commits:
                    commit_sha = commit['sha']
                    # 커밋 상세 조회 (변경된 파일 목록을 보기 위해)
                    commit_url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits/{commit_sha}"
                    c_res = requests.get(commit_url, headers=self.headers, timeout=5)
                    
                    if c_res.status_code == 200:
                        files = c_res.json().get('files', [])
                        for f in files:
                            filename = f['filename']
                            # 파일명 패턴: cves/2024/20xxx/CVE-2024-20353.json
                            if filename.endswith(".json") and "CVE-" in filename:
                                # 정규식으로 CVE ID 추출
                                match = re.search(r'(CVE-\d{4}-\d{4,7})', filename)
                                if match:
                                    cve_ids.add(match.group(1))
                
                result_list = list(cve_ids)
                print(f"[DEBUG] Extracted {len(result_list)} unique CVEs: {result_list}")
                return result_list
            else:
                print(f"[DEBUG] Error Response: {res.text}")
                return []
                
        except Exception as e:
            print(f"[ERR] Failed to fetch GitHub Commits: {e}")
            return []

    def enrich_cve(self, cve_id):
        """
        CVE 상세 정보 조회
        cvelistV5의 Raw JSON을 직접 당겨옵니다.
        """
        # CVE ID에서 연도와 디렉토리 구조 유추
        try:
            # CVE-YYYY-NNNNN
            parts = cve_id.split('-')
            year = parts[1]
            id_num = parts[2]
            # 1000단위로 디렉토리가 나뉨 (예: 12345 -> 12xxx)
            # 숫자가 적으면 Xxxx 처리
            if len(id_num) < 4:
                group_dir = "0xxx" # 매우 드문 케이스
            else:
                group_dir = id_num[:-3] + "xxx"

            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            
            res = requests.get(raw_url, timeout=5)
            data = {
                "id": cve_id,
                "cvss": 0.0,
                "description": "N/A (Failed to fetch details)"
            }

            if res.status_code == 200:
                json_data = res.json()
                
                # 1. Description 추출
                try:
                    desc_list = json_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                    for d in desc_list:
                        if d.get('lang') == 'en':
                            data['description'] = d.get('value')
                            break
                except: pass

                # 2. CVSS 추출 (V3.1 우선)
                try:
                    metrics = json_data.get('containers', {}).get('cna', {}).get('metrics', [])
                    for m in metrics:
                        if 'cvssV3_1' in m:
                            data['cvss'] = m['cvssV3_1'].get('baseScore', 0.0)
                            break
                except: pass
                
            return data

        except Exception as e:
            print(f"[WARN] Enrichment failed for {cve_id}: {e}")
            return {"id": cve_id, "cvss": 0.0, "description": "Error fetching details"}