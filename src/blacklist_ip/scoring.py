from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, x))


# ==========================================
# 카테고리별 임계값 오버라이드
# ==========================================
# 카테고리에 따라 위험 기준이 다름:
#   - botnet/C2: 더 낮은 임계값 (즉각 차단 필요)
#   - scanner/bruteforce: 약간 낮은 임계값
#   - tor: 높은 임계값 (단독으로는 위험하지 않음, 다중 소스 겹칠 때만)
#   - spam/proxy: 기본 임계값 유지
CATEGORY_THRESHOLD_OVERRIDES: Dict[str, Dict[str, int]] = {
    "botnet":      {"critical": 70, "high": 50, "medium": 30},
    "c2":          {"critical": 70, "high": 50, "medium": 30},
    "feodo":       {"critical": 70, "high": 50, "medium": 30},
    "malware":     {"critical": 70, "high": 50, "medium": 30},
    "bruteforce":  {"critical": 75, "high": 55, "medium": 35},
    "scanner":     {"critical": 75, "high": 55, "medium": 35},
    "exploit":     {"critical": 70, "high": 50, "medium": 30},
    "compromised": {"critical": 75, "high": 55, "medium": 35},
    "tor":         {"critical": 90, "high": 75, "medium": 50},
    # 나머지 카테고리는 글로벌 기본값 사용
}


def _match_category_override(category: str) -> Optional[Dict[str, int]]:
    """
    카테고리 문자열에서 키워드 부분 매칭.
    feeds.yml의 category는 "abuse.ch Feodo C2", "Tor exit nodes" 등 긴 문자열이므로
    키워드가 포함되어 있으면 해당 오버라이드를 적용.
    """
    if not category:
        return None
    cat_lower = category.lower().strip()

    # 정확 매칭 우선
    if cat_lower in CATEGORY_THRESHOLD_OVERRIDES:
        return CATEGORY_THRESHOLD_OVERRIDES[cat_lower]

    # 키워드 부분 매칭
    for keyword, overrides in CATEGORY_THRESHOLD_OVERRIDES.items():
        if keyword in cat_lower:
            return overrides

    return None


def risk_bucket(score: int, critical: int, high: int, medium: int,
                category: str = "") -> str:
    """
    카테고리별 임계값 오버라이드 지원.
    category 문자열에서 키워드를 부분 매칭하여 해당 임계값 적용.
    """
    overrides = _match_category_override(category)
    if overrides:
        critical = overrides["critical"]
        high = overrides["high"]
        medium = overrides["medium"]

    if score >= critical:
        return "Critical"
    if score >= high:
        return "High"
    if score >= medium:
        return "Medium"
    return "Low"


def compute_source_bonus(sources_count: int, step: int, cap: int) -> int:
    """
    다중 소스(여러 피드에 동시에 등장)일수록 신뢰도/중요도가 높을 가능성이 있어
    보수적으로 가산.
    """
    if sources_count <= 1:
        return 0
    return min(cap, step * (sources_count - 1))


def adjust_from_abuseipdb(abuse: Dict[str, Any]) -> int:
    """
    AbuseIPDB 세분화 스코어링.

    기존 5단계 버킷 → 연속적 점수로 변경하여 동점 IP 차별화.

    구성요소:
      1) confidence 기반: int(c * 0.25) → 0~25 (1점 단위 정밀도)
         - c < 10이면 페널티: -10 (false positive 가능성)
      2) 신고 건수 보너스: min(8, reports // 5) → 0~8
         - 신고가 많을수록 신뢰도 높음
      3) 신고 건수 < 3이면 전체 보정치 50% 감소 (낮은 신뢰도)

    총 범위: -10 ~ +33
    """
    c = abuse.get("abuseConfidenceScore")
    reports = abuse.get("totalReports")

    try:
        c = int(c)
    except Exception:
        return 0

    # 1) confidence 연속 점수
    if c < 10:
        adj = -10
    else:
        adj = int(c * 0.25)  # 10→2, 50→12, 80→20, 100→25

    # 2) 신고 건수 보너스
    try:
        if reports is not None:
            r = int(reports)
            adj += min(8, r // 5)  # 5건→1, 15건→3, 40건→8
    except Exception:
        pass

    # 3) 신고 건수 < 3이면 신뢰도 낮음
    try:
        if reports is not None and int(reports) < 3:
            adj = int(adj * 0.5)
    except Exception:
        pass

    return adj


def adjust_from_internetdb(inetdb: Dict[str, Any]) -> int:
    """
    Shodan InternetDB 세분화 스코어링 (v2.0).

    기존 3단계 버킷 → 위험 포트 수 + 알려진 취약점 수로 세분화.

    구성요소:
      1) 위험 포트: min(15, count * 3) → 0~15
      2) 알려진 취약점(vulns): min(10, len(vulns) * 2) → 0~10

    총 범위: 0 ~ +25
    """
    ports = inetdb.get("ports") or []
    if not isinstance(ports, list):
        ports = []

    risky_ports = {
        22,   # SSH
        23,   # Telnet
        3389, # RDP
        445,  # SMB
        9200, # Elasticsearch
        6379, # Redis
        11211,# Memcached
        27017,# MongoDB
        1433, # MSSQL
        3306, # MySQL
        5900, # VNC
        25,   # SMTP (오픈 릴레이/스팸 인프라 가능성)
    }

    risky_count = sum(1 for p in ports if isinstance(p, int) and p in risky_ports)
    port_adj = min(15, risky_count * 3)

    # 알려진 취약점 수 (InternetDB vulns 필드)
    vulns = inetdb.get("vulns") or []
    if not isinstance(vulns, list):
        vulns = []
    vuln_adj = min(10, len(vulns) * 2)

    return port_adj + vuln_adj


def adjust_from_duration(streak_days: int) -> int:
    """
    기간 기반 가중치.

    블랙리스트에 연속으로 오래 등장할수록 위험도가 높음.
    (단발성 오탐 vs 지속적 악성 IP 구분)

    스코어링:
      1일(신규): 0
      2일: +2
      3일: +4
      4일: +6
      5일: +8
      6일: +10
      7일+: +12 (cap)

    총 범위: 0 ~ +12
    """
    if streak_days <= 1:
        return 0
    return min(12, (streak_days - 1) * 2)


def apply_scoring(
    tier1_records: Dict[str, Any],
    enrichment: Dict[str, Dict[str, Any]],
    critical: int,
    high: int,
    medium: int,
    enable_source_bonus: bool,
    source_bonus_step: int,
    source_bonus_cap: int,
    streak_data: Optional[Dict[str, int]] = None,
) -> Dict[str, Dict[str, Any]]:
    """
    Input:
      tier1_records: {indicator: IndicatorRecord-like}
      enrichment: {ip: {"abuseipdb": {...}?, "internetdb": {...}?}}
      streak_data: {indicator: consecutive_days} (optional, 기간 기반 가중치)

    Output:
      scored: {
        indicator: {
          indicator, type, category, sources, base_score,
          final_score, risk, enrichment, adjustments
        }
      }
    """
    out: Dict[str, Dict[str, Any]] = {}
    streaks = streak_data or {}

    for ind, rec in tier1_records.items():
        base = int(rec.base_score)
        sources = list(rec.sources)

        bonus = (
            compute_source_bonus(len(sources), source_bonus_step, source_bonus_cap)
            if enable_source_bonus
            else 0
        )

        enr = enrichment.get(ind) if enrichment else None
        abuse_adj = 0
        inetdb_adj = 0

        if enr:
            abuse = enr.get("abuseipdb")
            if isinstance(abuse, dict):
                abuse_adj = adjust_from_abuseipdb(abuse)

            inetdb = enr.get("internetdb")
            if isinstance(inetdb, dict):
                inetdb_adj = adjust_from_internetdb(inetdb)

        # 기간 기반 가중치
        duration_adj = adjust_from_duration(streaks.get(ind, 0))

        final_score = clamp(base + bonus + abuse_adj + inetdb_adj + duration_adj)

        # 카테고리별 임계값 적용
        category = rec.category if hasattr(rec, 'category') else ""
        risk = risk_bucket(final_score, critical, high, medium, category=category)

        out[ind] = {
            "indicator": ind,
            "type": rec.type,
            "category": category,
            "sources": sources,
            "base_score": base,
            "final_score": final_score,
            "risk": risk,
            "enrichment": enr,
            "adjustments": {
                "source_bonus": bonus,
                "abuseipdb": abuse_adj,
                "internetdb": inetdb_adj,
                "duration": duration_adj,
            },
        }

    return out