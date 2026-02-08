import re

def safe_str(x):
    return "" if x is None else str(x)

def compact_whitespace(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip()

def truncate(s: str, n: int) -> str:
    s = s or ""
    return s if len(s) <= n else s[:n-1] + "…"
