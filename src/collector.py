import requests
import datetime
import pytz
from tenacity import retry, stop_after_attempt, wait_fixed

class Collector:
    def __init__(self):
        self.kev_set = set()
        self.epss_cache = {}

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5))
    def fetch_kev(self):
        """CISA KEV 카탈로그 로드"""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        res = requests.get(url, timeout=10)
        if res.status_code == 200:
            data = res.json()
            self.kev_set = {vuln['cveID'] for vuln in data['vulnerabilities']}
            print(f"[INFO] Loaded {len(self.kev_set)} KEVs")

    def fetch_epss(self, cve_ids):
        """First.org에서 EPSS 일괄 조회"""
        if not cve_ids: return
        
        # 쉼표로 구분하여 배치 조회
        ids_str = ",".join(cve_ids[:100]) # API 제한 고려 100개씩 끊기 권장
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
        """cve.org에서 최근 변경된 PUBLISHED CVE 조회"""
        now = datetime.datetime.now(pytz.UTC)
        start_time = now - datetime.timedelta(hours=hours)
        # 시간 형식: 2024-02-08T00:00:00.000Z
        time_str = start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        
        url = f"https://cveawg.mitre.org/api/cve/history?time_start={time_str}&change_type=PUBLISHED"
        
        try:
            res = requests.get(url, timeout=10)
            if res.status_code == 200:
                # cve.org API 응답 구조 파싱
                # 응답 예: { "cveRecords": [ { "cveMetadata": { "cveId": "..." } } ] }
                records = res.json().get('cveRecords', [])
                # ID만 추출
                return [r['cveMetadata']['cveId'] for r in records]
        except Exception as e:
            print(f"[ERR] Failed to fetch CVE history: {e}")
            return []
        return []

    def enrich_cve(self, cve_id):
        """CVE 상세 정보 조회 (CVSS 파싱 등)"""
        # MVP에서는 cve.org 상세 API 사용
        url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
        data = {
            "id": cve_id,
            "cvss": 0.0,
            "description": "N/A"
        }
        
        try:
            res = requests.get(url, timeout=5)
            if res.status_code == 200:
                raw = res.json()
                # 간단한 CVSS 파싱 (JSON 경로가 복잡하므로 예외처리 필수)
                containers = raw.get('containers', {}).get('cna', {})
                metrics = containers.get('metrics', [])
                
                # CVSS V3.1 찾기
                for m in metrics:
                    if 'cvssV3_1' in m:
                        data['cvss'] = m['cvssV3_1'].get('baseScore', 0.0)
                        break
                
                desc = containers.get('descriptions', [{}])[0].get('value', 'N/A')
                data['description'] = desc
        except:
            pass
            
        return data