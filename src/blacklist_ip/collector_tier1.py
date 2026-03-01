import ipaddress
import re
import requests
import yaml
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any


@dataclass
class FeedDef:
    name: str
    url: str
    format: str  # plain_ip | cidr | csv_simple
    base_score: int
    category: str


@dataclass
class IndicatorRecord:
    indicator: str        # ip or cidr string
    type: str             # ip|cidr
    category: str
    sources: List[str] = field(default_factory=list)
    base_score: int = 0


def _normalize_ip(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value)
        return str(ip)
    except Exception:
        return None


def _normalize_cidr(value: str) -> Optional[str]:
    value = value.strip()
    if not value:
        return None
    try:
        net = ipaddress.ip_network(value, strict=False)
        return str(net)
    except Exception:
        return None


# IPv4 우선. (IPv6가 필요하면 추후 확장)
_IPV4_RE = re.compile(r"(?:(?:\d{1,3}\.){3}\d{1,3})")


def _extract_ipv4_tokens(text: str) -> List[str]:
    return _IPV4_RE.findall(text)


def load_feeds(feeds_path: str) -> List[FeedDef]:
    with open(feeds_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    feeds = []
    for item in data.get("feeds", []):
        feeds.append(
            FeedDef(
                name=item["name"],
                url=item["url"],
                format=str(item["format"]).strip(),
                base_score=int(item["base_score"]),
                category=item.get("category", item["name"]),
            )
        )
    return feeds


def download_text(url: str, timeout: int = 30) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text


def parse_feed(feed: FeedDef, raw_text: str) -> List[str]:
    fmt = feed.format.lower().strip()
    indicators: List[str] = []

    if fmt == "plain_ip":
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 라인 안에 IP가 섞여있을 수 있으니 token extract
            tokens = _extract_ipv4_tokens(line)
            for t in tokens:
                ip = _normalize_ip(t)
                if ip:
                    indicators.append(ip)

    elif fmt == "cidr":
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # "1.2.3.0/24 ; comment" 형태 대응
            first = line.split()[0].split(";")[0].strip()
            cidr = _normalize_cidr(first)
            if cidr:
                indicators.append(cidr)

    elif fmt == "csv_simple":
        # 매우 단순 CSV: 첫 컬럼이 IP라고 가정
        for line in raw_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            first = line.split(",")[0].strip()
            ip = _normalize_ip(first)
            if ip:
                indicators.append(ip)

    else:
        raise ValueError(f"Unsupported feed format: {feed.format}")

    return indicators


def _merge_records(merged: Dict[str, IndicatorRecord], feed: FeedDef, indicators: List[str]) -> None:
    for ind in indicators:
        ind_type = "cidr" if "/" in ind else "ip"
        rec = merged.get(ind)
        if rec is None:
            merged[ind] = IndicatorRecord(
                indicator=ind,
                type=ind_type,
                category=feed.category,
                sources=[feed.name],
                base_score=feed.base_score,
            )
        else:
            if feed.name not in rec.sources:
                rec.sources.append(feed.name)
            # base_score 대표 규칙: max
            if feed.base_score > rec.base_score:
                rec.base_score = feed.base_score
                rec.category = feed.category


def collect_tier1(feeds_path: str) -> Dict[str, IndicatorRecord]:
    """
    Strict 모드: 예외를 올림.
    """
    feeds = load_feeds(feeds_path)
    merged: Dict[str, IndicatorRecord] = {}

    for feed in feeds:
        text = download_text(feed.url)
        indicators = parse_feed(feed, text)
        _merge_records(merged, feed, indicators)

    return merged


def collect_tier1_safe(feeds_path: str) -> Tuple[Dict[str, IndicatorRecord], List[Dict[str, Any]]]:
    """
    Safe 모드:
      - 피드별 실패는 기록하고 계속 진행
      - 반환: (records, feed_failures)

    feed_failures element:
      {"feed": name, "url": url, "error": "..."}
    """
    feeds = load_feeds(feeds_path)
    merged: Dict[str, IndicatorRecord] = {}
    failures: List[Dict[str, Any]] = []

    for feed in feeds:
        try:
            text = download_text(feed.url)
            indicators = parse_feed(feed, text)
            _merge_records(merged, feed, indicators)
        except Exception as e:
            failures.append({
                "feed": feed.name,
                "url": feed.url,
                "error": str(e),
            })
            continue

    return merged, failures