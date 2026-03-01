import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Quotas:
    abuseipdb_daily_max: int = 1000
    internetdb_daily_max: int = 10_000


@dataclass(frozen=True)
class CacheTTLHours:
    abuseipdb: int = 24
    internetdb: int = 72


@dataclass(frozen=True)
class ProviderTimeoutSec:
    abuseipdb: int = 20
    internetdb: int = 10


@dataclass(frozen=True)
class ProviderRateLimit:
    abuseipdb_min_interval: float = 1.0
    internetdb_min_interval: float = 0.1


@dataclass(frozen=True)
class Settings:
    # Required integrations
    slack_webhook_url: str
    supabase_url: str
    supabase_key: str

    # Tier2 keys
    abuseipdb_api_key: Optional[str]

    # Tier1 feeds
    feeds_path: str = "src/blacklist_ip/feeds.yml"

    # Risk thresholds
    critical_threshold: int = 80
    high_threshold: int = 60
    medium_threshold: int = 40

    # Source bonus policy
    enable_source_bonus: bool = True
    source_bonus_step: int = 5
    source_bonus_cap: int = 15

    # Reporting
    topn_report: int = 10

    # Enrichment 제한 (GitHub Actions 30분 타임아웃 방어)
    max_enrich_count: int = 500  # 최대 enrichment 대상 IP 수
    enrich_workers: int = 10     # InternetDB 병렬 워커 수

    quotas: Quotas = Quotas()
    cache_ttl_hours: CacheTTLHours = CacheTTLHours()
    timeouts: ProviderTimeoutSec = ProviderTimeoutSec()
    ratelimit: ProviderRateLimit = ProviderRateLimit()


def load_settings() -> Settings:
    slack = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    sb_url = os.getenv("SUPABASE_URL", "").strip()
    sb_key = os.getenv("SUPABASE_KEY", "").strip()

    if not slack:
        raise RuntimeError("SLACK_WEBHOOK_URL is required")
    if not sb_url or not sb_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required (delta persistence)")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip() or None

    return Settings(
        slack_webhook_url=slack,
        supabase_url=sb_url,
        supabase_key=sb_key,
        abuseipdb_api_key=abuse_key,
    )