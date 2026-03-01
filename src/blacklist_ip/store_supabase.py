import datetime as dt
from typing import Any, Dict, Optional, Set, List

from supabase import create_client, Client


class Store:
    def __init__(self, supabase_url: str, supabase_key: str):
        self.sb: Client = create_client(supabase_url, supabase_key)

    # -------------------------
    # Snapshot for delta
    # -------------------------
    def get_snapshot_indicator_set(self, date: dt.date) -> Set[str]:
        """
        특정 날짜(date)의 전체 indicator set을 로드.
        (어제 set vs 오늘 set 델타 계산용)
        """
        res = (
            self.sb.table("shield_indicators")
            .select("indicator")
            .eq("date", date.isoformat())
            .execute()
        )
        rows = res.data or []
        return set(r["indicator"] for r in rows if isinstance(r, dict) and "indicator" in r)

    def upsert_snapshot(
        self,
        date: dt.date,
        scored: Dict[str, Dict[str, Any]],
        new_count: int,
        removed_count: int,
        api_usage: Dict[str, Any],
    ) -> None:
        """
        1) shield_daily_snapshots: 일별 메타 저장(upsert)
        2) shield_indicators: 일별 indicator 저장(upsert)
        """
        meta = {
            "date": date.isoformat(),
            "total_count": len(scored),
            "new_count": int(new_count),
            "removed_count": int(removed_count),
            "api_usage": api_usage,
        }
        self.sb.table("shield_daily_snapshots").upsert(meta).execute()

        payload: List[Dict[str, Any]] = []
        for ind, r in scored.items():
            payload.append({
                "date": date.isoformat(),
                "indicator": ind,
                "type": r["type"],
                "category": r.get("category"),
                "sources": r.get("sources", []),
                "base_score": int(r.get("base_score", 0)),
                "final_score": int(r.get("final_score", 0)),
                "risk": r.get("risk", "Low"),
                "enrichment": r.get("enrichment"),
            })

        CHUNK = 1000
        for i in range(0, len(payload), CHUNK):
            self.sb.table("shield_indicators").upsert(payload[i:i + CHUNK]).execute()

    def get_highrisk_indicators(self, date: dt.date) -> List[Dict[str, Any]]:
        try:
            res = (
                self.sb.table("shield_indicators")
                .select("indicator, final_score, risk, category")
                .eq("date", date.isoformat())
                .in_("risk", ["Critical", "High"])
                .order("final_score", desc=True)
                .limit(100)
                .execute()
            )
            return res.data or []
        except Exception:
            return []

    def get_indicator_streak(self, indicators: list, today: dt.date, lookback_days: int = 7) -> dict:
        """
        각 indicator가 최근 N일 동안 몇 일 연속 등장했는지 반환.
        Returns: {indicator: streak_days}  (streak_days = 1~lookback_days)
        """
        if not indicators:
            return {}

        streak: dict = {}
        # 최근 N일 날짜 목록 (어제부터 역순)
        dates = [(today - dt.timedelta(days=d)).isoformat() for d in range(1, lookback_days + 1)]

        # 날짜별 indicator set 조회 (캐시 효율을 위해 날짜 단위)
        daily_sets: list = []
        for d in dates:
            try:
                res = (
                    self.sb.table("shield_indicators")
                    .select("indicator")
                    .eq("date", d)
                    .in_("indicator", indicators[:200])
                    .execute()
                )
                day_set = set(r["indicator"] for r in (res.data or []) if isinstance(r, dict))
                daily_sets.append(day_set)
            except Exception:
                daily_sets.append(set())

        # 연속 등장 일수 계산 (어제부터 역순으로 끊기면 중단)
        for ind in indicators:
            count = 0
            for day_set in daily_sets:
                if ind in day_set:
                    count += 1
                else:
                    break  # 연속 끊김
            if count > 0:
                streak[ind] = count

        return streak

    # -------------------------
    # Enrichment cache
    # -------------------------
    def get_cache(self, indicator: str, provider: str) -> Optional[Dict[str, Any]]:
        now = dt.datetime.now(dt.timezone.utc).isoformat()

        res = (
            self.sb.table("shield_enrichment_cache")
            .select("data, ttl_until")
            .eq("indicator", indicator)
            .eq("provider", provider)
            .gt("ttl_until", now)
            .limit(1)
            .execute()
        )
        rows = res.data or []
        if not rows:
            return None
        row = rows[0]
        if not isinstance(row, dict):
            return None
        data = row.get("data")
        return data if isinstance(data, dict) else data  # dict가 아니어도 그대로 반환(호출부에서 방어)

    def put_cache(self, indicator: str, provider: str, data: Dict[str, Any], ttl_until: dt.datetime) -> None:
        payload = {
            "indicator": indicator,
            "provider": provider,
            "data": data,
            "ttl_until": ttl_until.isoformat(),
        }
        self.sb.table("shield_enrichment_cache").upsert(payload).execute()