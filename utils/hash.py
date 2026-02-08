import hashlib
import json

def sha256_text(s: str) -> str:
    return hashlib.sha256((s or "").encode("utf-8")).hexdigest()

def stable_hash(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True)
    return sha256_text(raw)
