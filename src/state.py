import datetime
import json
import os
from typing import Dict, Optional, Set, Tuple

import pytz

from logger import logger

_STATE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "docs", "data", "pipeline_state.json"
)
_DB_HANDLE = None


def _db():
    global _DB_HANDLE
    if _DB_HANDLE is not None:
        return _DB_HANDLE or None
    if not os.environ.get("SUPABASE_URL") or not os.environ.get("SUPABASE_KEY"):
        return None
    try:
        from database import ArgusDB
        _DB_HANDLE = ArgusDB()
    except Exception as e:
        logger.warning(f"상태 DB 연결 실패 → 파일 경로로 진행: {e}")
        _DB_HANDLE = False
    return _DB_HANDLE or None


def _read_state() -> Dict:
    db = _db()
    if db is not None:
        state = db.get_pipeline_state()
        if state:
            return state
        logger.info("DB에 파이프라인 상태 없음 → 파일에서 이어받기 시도")
    try:
        with open(_STATE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _write_state(payload: Dict) -> None:
    db = _db()
    if db is not None and db.set_pipeline_state(payload):
        return
    try:
        os.makedirs(os.path.dirname(_STATE_PATH), exist_ok=True)
        with open(_STATE_PATH, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=1, sort_keys=True)
    except OSError as e:
        logger.warning(f"상태 파일 저장 실패: {e}")

def read_watermark() -> Optional[datetime.datetime]:
    wm = _read_state().get("last_processed_until")
    if wm:
        try:
            return datetime.datetime.fromisoformat(str(wm).replace("Z", "+00:00"))
        except ValueError:
            logger.warning(f"워터마크 파싱 실패({wm!r}) → 부트스트랩")
    return None

def read_failure_state() -> Tuple[Dict[str, int], Dict[str, str]]:
    data = _read_state()
    fails = data.get("failures") or {}
    quarantined = data.get("quarantined") or {}
    return (
        {k: int(v) for k, v in fails.items() if isinstance(v, (int, float))},
        {k: str(v) for k, v in quarantined.items()},
    )

def read_rpd_state() -> Dict[str, Dict[str, int]]:
    rpd = _read_state().get("rpd")
    return rpd if isinstance(rpd, dict) else {}

def iso_after(ts: str, cutoff: datetime.datetime) -> bool:
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")) >= cutoff
    except ValueError:
        return True


def active_quarantine(quarantined: Dict[str, str], retry_after_hours: int) -> Set[str]:
    now = datetime.datetime.now(pytz.UTC)
    active = set()
    for cid, ts in quarantined.items():
        try:
            when = datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        except ValueError:
            continue
        if (now - when) < datetime.timedelta(hours=retry_after_hours):
            active.add(cid)
    return active

def write_watermark(dt_utc: datetime.datetime,
                    failures: Optional[Dict[str, int]] = None,
                    quarantined: Optional[Dict[str, str]] = None,
                    rpd: Optional[Dict[str, Dict[str, int]]] = None) -> None:
    payload = _read_state()
    payload["last_processed_until"] = dt_utc.astimezone(pytz.UTC).isoformat()
    for key, value in (("failures", failures), ("quarantined", quarantined)):
        if value:
            payload[key] = value
        else:
            payload.pop(key, None)
    if rpd is not None:
        if rpd:
            payload["rpd"] = rpd
        else:
            payload.pop("rpd", None)
    _write_state(payload)
    logger.info(f"워터마크 저장: {payload['last_processed_until']}")

def read_backfill_offset() -> int:
    v = _read_state().get("translation_scan_offset")
    return v if isinstance(v, int) and v >= 0 else 0


def write_backfill_offset(offset: int) -> None:
    data = _read_state()
    data["translation_scan_offset"] = max(0, int(offset))
    _write_state(data)


def write_rpd_state(rpd: Dict[str, Dict[str, int]]) -> None:
    data = _read_state()
    if rpd:
        data["rpd"] = rpd
    else:
        data.pop("rpd", None)
    _write_state(data)
