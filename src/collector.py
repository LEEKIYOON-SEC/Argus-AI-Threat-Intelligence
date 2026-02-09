import requests
import datetime
import pytz
import os
import re

class Collector:
    def __init__(self):
        self.kev_set = set()
        self.epss_cache = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }

    def fetch_kev(self):
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                self.kev_set = {vuln['cveID'] for vuln in res.json()['vulnerabilities']}
                print(f"[INFO] Loaded {len(self.kev_set)} KEVs")
        except: pass

    def fetch_epss(self, cve_ids):
        if not cve_ids: return
        chunk_size = 50
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
            try:
                res = requests.get(url, timeout=10)
                if res.status_code == 200:
                    for item in res.json().get('data', []):
                        self.epss_cache[item['cve']] = float(item['epss'])
            except: pass

    def fetch_recent_cves(self, hours=2):
        now = datetime.datetime.now(pytz.UTC)
        since_str = (now - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?since={since_str}"
        try:
            res = requests.get(url, headers=self.headers, timeout=10)
            if res.status_code == 200:
                cve_ids = set()
                for commit in res.json():
                    c_res = requests.get(commit['url'], headers=self.headers, timeout=5)
                    if c_res.status_code == 200:
                        for f in c_res.json().get('files', []):
                            filename = f['filename']
                            if filename.endswith(".json") and "CVE-" in filename:
                                match = re.search(r'(CVE-\d{4}-\d{4,7})', filename)
                                if match: cve_ids.add(match.group(1))
                return list(cve_ids)
            return []
        except: return []

    def enrich_cve(self, cve_id):
        """CVE 상세 정보 조회 (Title 및 CVSS 강화)"""
        try:
            parts = cve_id.split('-')
            year, id_num = parts[1], parts[2]
            group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            
            res = requests.get(raw_url, timeout=5)
            # 기본 데이터 구조 (Title 추가됨)
            data = {
                "id": cve_id, 
                "title": "N/A", 
                "cvss": 0.0, 
                "description": "N/A", 
                "state": "UNKNOWN"
            }
            
            if res.status_code == 200:
                json_data = res.json()
                cna = json_data.get('containers', {}).get('cna', {})
                
                data['state'] = json_data.get('cveMetadata', {}).get('state', 'UNKNOWN')
                data['title'] = cna.get('title', 'N/A')
                
                # Description 추출
                try:
                    for d in cna.get('descriptions', []):
                        if d.get('lang') == 'en':
                            data['description'] = d.get('value')
                            break
                except: pass
                
                # CVSS 점수 추출 (V4 -> V3.1 -> V3.0 순서)
                try:
                    metrics = cna.get('metrics', [])
                    for m in metrics:
                        if 'cvssV4_0' in m:
                            data['cvss'] = m['cvssV4_0'].get('baseScore', 0.0)
                            break
                        elif 'cvssV3_1' in m:
                            data['cvss'] = m['cvssV3_1'].get('baseScore', 0.0)
                            break
                        elif 'cvssV3_0' in m:
                            data['cvss'] = m['cvssV3_0'].get('baseScore', 0.0)
                            break
                except: pass
                
            return data
        except: return {"id": cve_id, "title": "Error", "cvss": 0.0, "description": "Error", "state": "ERROR"}