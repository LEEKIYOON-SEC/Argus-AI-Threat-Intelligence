from datetime import datetime, timedelta, timezone

def utc_now():
    return datetime.now(timezone.utc)

def utc_iso(dt: datetime):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def utc_minutes_ago(minutes: int):
    return utc_now() - timedelta(minutes=minutes)
