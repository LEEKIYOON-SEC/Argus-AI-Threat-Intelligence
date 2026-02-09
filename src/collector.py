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
        """CVE 상세 정보 및 상태(PUBLISHED 여부) 조회"""
        try:
            parts = cve_id.split('-')
            year, id_num = parts[1], parts[2]
            group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            
            res = requests.get(raw_url, timeout=5)
            data = {"id": cve_id, "cvss": 0.0, "description": "N/A", "state": "UNKNOWN"}
            
            if res.status_code == 200:
                json_data = res.json()
                data['state'] = json_data.get('cveMetadata', {}).get('state', 'UNKNOWN')
                try:
                    descriptions = json_data.get('containers', {}).get('cna', {}).get('descriptions', [])
                    for d in descriptions:
                        if d.get('lang') == 'en':
                            data['description'] = d.get('value')
                            break
                except: pass
                try:
                    metrics = json_data.get('containers', {}).get('cna', {}).get('metrics', [])
                    for m in metrics:
                        if 'cvssV3_1' in m:
                            data['cvss'] = m['cvssV3_1'].get('baseScore', 0.0)
                            break
                except: pass
            return data
        except: return {"id": cve_id, "cvss": 0.0, "description": "Error", "state": "ERROR"}