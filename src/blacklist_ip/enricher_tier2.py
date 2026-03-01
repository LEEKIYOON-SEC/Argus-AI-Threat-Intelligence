import datetime as dt
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional



@dataclass
class APIUsage:
    abuseipdb: int = 0
    internetdb: int = 0


class SimpleRateLimiter:
    def __init__(self, min_interval_sec: float):
        self.min_interval_sec = max(0.0, float(min_interval_sec))
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval_sec <= 0:
            return
        now = time.time()
        elapsed = now - self._last
        if elapsed < self.min_interval_sec:
            time.sleep(self.min_interval_sec - elapsed)
        self._last = time.time()


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        j = resp.json()
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


class Enricher:
    def __init__(
        self,
        abuseipdb_key: Optional[str],
        store,  # store_supabase.Store
        quotas,
        cache_ttl_hours,
        timeouts,
        ratelimit,
        max_enrich: int = 500,
        workers: int = 10,
    ):
        self.abuseipdb_key = abuseipdb_key
        self.store = store
        self.quotas = quotas
        self.cache_ttl_hours = cache_ttl_hours
        self.timeouts = timeouts
        self.ratelimit = ratelimit
        self.max_enrich = max_enrich
        self.workers = workers

        self.usage = APIUsage()

        self.rl_abuse = SimpleRateLimiter(self.ratelimit.abuseipdb_min_interval)

    def enrich_many(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        신규 IP enrichment (v2.0 - 2단계 처리).

        Phase 1: AbuseIPDB 순차 처리 (rate limit 1req/s)
        Phase 2: InternetDB 병렬 처리 (ThreadPoolExecutor)

        returns:
          {
            "1.2.3.4": {
               "abuseipdb": {...}?,
               "internetdb": {...}?
            },
            ...
          }
        """
        # 하드캡 적용
        target_ips = ips[:self.max_enrich]
        skipped = len(ips) - len(target_ips)
        total = len(target_ips)

        if skipped > 0:
            print(f"  [Enricher] 대상: {total}개 (하드캡 {self.max_enrich}), 스킵: {skipped}개", flush=True)
        else:
            print(f"  [Enricher] 대상: {total}개", flush=True)

        if total == 0:
            return {}

        result: Dict[str, Dict[str, Any]] = {ip: {} for ip in target_ips}

        # ── Phase 1: AbuseIPDB (순차 - rate limit 1req/s) ──
        if self.abuseipdb_key:
            abuse_quota = int(self.quotas.abuseipdb_daily_max)
            abuse_target = min(total, abuse_quota)
            print(f"  [AbuseIPDB] 순차 enrichment 시작 (quota: {abuse_quota})", flush=True)
            start = time.time()

            for i, ip in enumerate(target_ips, 1):
                if self.usage.abuseipdb >= abuse_quota:
                    print(f"  [AbuseIPDB] quota 소진 ({abuse_quota}), 중단", flush=True)
                    break

                abuse = self._get_cached_or_fetch_abuseipdb(ip)
                if abuse is not None:
                    result[ip]["abuseipdb"] = abuse

                if i % 100 == 0 or i == abuse_target:
                    pct = (i / abuse_target * 100)
                    print(f"  [AbuseIPDB] {i}/{abuse_target} ({pct:.0f}%)", flush=True)

            elapsed = time.time() - start
            print(f"  [AbuseIPDB] 완료: {self.usage.abuseipdb}건 ({elapsed:.1f}s)", flush=True)

        # ── Phase 2: InternetDB (병렬 - ThreadPoolExecutor) ──
        inetdb_quota = int(self.quotas.internetdb_daily_max)
        inetdb_targets = target_ips[:inetdb_quota]

        if inetdb_targets:
            print(f"  [InternetDB] 병렬 enrichment 시작 (workers: {self.workers}, 대상: {len(inetdb_targets)}개)", flush=True)
            start = time.time()
            done_count = 0
            inetdb_total = len(inetdb_targets)

            with ThreadPoolExecutor(max_workers=self.workers) as executor:
                future_to_ip = {
                    executor.submit(self._fetch_internetdb_safe, ip): ip
                    for ip in inetdb_targets
                }

                for future in as_completed(future_to_ip):
                    ip = future_to_ip[future]
                    done_count += 1
                    try:
                        data = future.result()
                        if data is not None:
                            result[ip]["internetdb"] = data
                            self.usage.internetdb += 1

                            # 캐시 저장
                            try:
                                ttl = _utc_now() + dt.timedelta(hours=int(self.cache_ttl_hours.internetdb))
                                self.store.put_cache(ip, "internetdb", data, ttl)
                            except Exception:
                                pass
                    except Exception:
                        pass

                    if done_count % 100 == 0 or done_count == inetdb_total:
                        pct = (done_count / inetdb_total * 100)
                        print(f"  [InternetDB] {done_count}/{inetdb_total} ({pct:.0f}%)", flush=True)

            elapsed = time.time() - start
            print(f"  [InternetDB] 완료: {self.usage.internetdb}건 ({elapsed:.1f}s)", flush=True)

        return result

    # -------------------------
    # AbuseIPDB
    # -------------------------
    def _get_cached_or_fetch_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.abuseipdb_key:
            return None

        cached = self.store.get_cache(ip, "abuseipdb")
        if cached is not None:
            return cached

        if self.usage.abuseipdb >= int(self.quotas.abuseipdb_daily_max):
            return None

        try:
            self.rl_abuse.wait()
            data = self._fetch_abuseipdb(ip)
            self.usage.abuseipdb += 1

            ttl = _utc_now() + dt.timedelta(hours=int(self.cache_ttl_hours.abuseipdb))
            self.store.put_cache(ip, "abuseipdb", data, ttl)
            return data
        except Exception:
            # 부분 실패 허용: 이 IP의 abuseipdb는 결측으로 남김
            return None

    def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""  # verbose mode
        }

        r = requests.get(url, headers=headers, params=params, timeout=int(self.timeouts.abuseipdb))
        r.raise_for_status()
        j = _safe_json(r)
        # 핵심만 저장(응답 전체를 저장하면 DB 비용 증가)
        data = j.get("data", {}) if isinstance(j.get("data", {}), dict) else {}
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "lastReportedAt": data.get("lastReportedAt"),
            "countryCode": data.get("countryCode"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames"),
        }

    # -------------------------
    # Shodan InternetDB
    # -------------------------
    def _fetch_internetdb_safe(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        InternetDB fetch (병렬 처리용, 예외를 None으로 반환).
        캐시 확인 포함.
        """
        # 캐시 확인
        try:
            cached = self.store.get_cache(ip, "internetdb")
            if cached is not None:
                return cached
        except Exception:
            pass

        try:
            return self._fetch_internetdb(ip)
        except Exception:
            return None

    def _fetch_internetdb(self, ip: str) -> Dict[str, Any]:
        """
        InternetDB는 보통 아래 형태로 응답:
        {
          "ip": "1.2.3.4",
          "ports": [80, 443],
          "hostnames": [],
          "tags": [],
          "cpes": [],
          "vulns": []
        }

        NOTE:
        - 없는 IP는 404로 올 수 있음 -> 예외로 처리되어 None 반환(호출부에서)
        """
        url = f"https://internetdb.shodan.io/{ip}"
        r = requests.get(url, timeout=int(self.timeouts.internetdb))
        if r.status_code == 404:
            # 데이터 없음은 정상 케이스
            raise RuntimeError("InternetDB: not found")
        r.raise_for_status()
        j = _safe_json(r)

        ports = j.get("ports", [])
        if not isinstance(ports, list):
            ports = []

        # 저장 비용을 위해 최소만
        return {
            "ports": [p for p in ports if isinstance(p, int)],
            "tags": j.get("tags", []),
            "cpes": j.get("cpes", []),
            "vulns": j.get("vulns", []),
            "hostnames": j.get("hostnames", []),
        }