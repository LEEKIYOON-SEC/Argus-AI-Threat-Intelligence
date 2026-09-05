import re

CVE_RE = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
CWE_RE = re.compile(r'CWE-\d{1,4}\b')

_JUNK = ("", "unknown", "n/a", "-", "n/a (단일 버전)", "정보 없음")


def meaningful(v) -> str:
    s = str(v or "").strip()
    return "" if s.lower() in _JUNK else s
