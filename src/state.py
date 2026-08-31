"""파이프라인 진행 상태 — 워터마크·실패 추적·일일 요청 수·백필 위치.

원래 collector.py 안에 있었는데, 수집 경로를 delta 피드로 갈아끼우면서 분리했다.
이 값들은 '무엇을 어디서 읽는가'와 무관한 **실행 간 연속성**에 관한 것이고,
fast-lane과 bulk-lane이 함께 쓴다.

저장 위치는 Supabase pipeline_state 테이블(1행). 예전에는 docs/data/에 파일로 두고
매 실행 커밋해 영속시켰는데, 그것 때문에 시간당 커밋이 1건씩 쌓였다.
아래 파일 경로는 자격증명 없이 도는 로컬 실행용 폴백으로만 남는다.
"""
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
_DB_HANDLE = None   # 상태 조회/저장이 한 실행에서 여러 번 일어나므로 붙여 쓴다


def _db():
    """상태 저장용 DB 핸들. 자격증명이 없으면 None (로컬 실행·테스트)."""
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
        _DB_HANDLE = False   # 재시도하지 않는다 (매번 예외를 내며 느려지는 것 방지)
    return _DB_HANDLE or None


def _read_state() -> Dict:
    """상태 전체를 읽는다 (워터마크 + 실패 추적 + RPD). 없으면 빈 dict.

    DB 우선, 없으면 파일. 파일 경로는 두 가지를 위해 남는다 — DB로 옮기기 전 마지막
    커밋본에서 워터마크를 이어받는 전환기, 그리고 자격증명 없이 도는 로컬 실행."""
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
    """상태를 저장한다. DB가 있으면 DB에, 없으면 파일에."""
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
    """마지막으로 소비한 배치 시각(UTC). 없거나 깨졌으면 None.

    None일 때의 소급 기간은 feed가 정한다(feed.BOOTSTRAP_HOURS). 기본값을 두 곳에 두면
    한쪽만 고쳐져 조용히 갈라지므로, 여기서는 '모른다'만 알린다."""
    wm = _read_state().get("last_processed_until")
    if wm:
        try:
            return datetime.datetime.fromisoformat(str(wm).replace("Z", "+00:00"))
        except ValueError:
            logger.warning(f"워터마크 파싱 실패({wm!r}) → 부트스트랩")
    return None

def read_failure_state() -> Tuple[Dict[str, int], Dict[str, str]]:
    """(연속 실패 횟수, 격리 목록) 반환. 격리 = {cve_id: 격리 시각 ISO}."""
    data = _read_state()
    fails = data.get("failures") or {}
    quarantined = data.get("quarantined") or {}
    return (
        {k: int(v) for k, v in fails.items() if isinstance(v, (int, float))},
        {k: str(v) for k, v in quarantined.items()},
    )

def read_rpd_state() -> Dict[str, Dict[str, int]]:
    """이전 실행이 남긴 일일 요청 수(RPD) 버킷. 없으면 빈 dict.

    프로세스는 매 실행 새로 뜨므로 메모리 카운터만으로는 항상 0에서 시작한다 —
    시간당 실행되는 파이프라인에서는 무료 티어 일일 한도(Gemma 1,500)를 스스로
    지킬 수 없어 공급자가 429로 끊어버린다. 워터마크와 같은 파일에 이어붙인다."""
    rpd = _read_state().get("rpd")
    return rpd if isinstance(rpd, dict) else {}

def iso_after(ts: str, cutoff: datetime.datetime) -> bool:
    """ISO 시각 문자열이 cutoff 이후인가. 파싱 실패 시 True — 못 읽는 값을 근거로
    격리를 임의 해제하지 않기 위해서다(안전한 쪽으로 틀린다)."""
    try:
        return datetime.datetime.fromisoformat(str(ts).replace("Z", "+00:00")) >= cutoff
    except ValueError:
        return True


def active_quarantine(quarantined: Dict[str, str], retry_after_hours: int) -> Set[str]:
    """아직 격리 유효기간이 지나지 않은 CVE 집합. 기간이 지나면 자동 해제되어 재시도된다
    (일시 장애가 연속으로 겹쳐 격리된 경우 스스로 회복하게 하는 안전장치)."""
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
    """처리 완료 지점(UTC) + 실패 추적 상태 + 일일 요청 수(RPD)를 기록.

    실패 추적은 '독약 레코드'가 워터마크를 영구 고정하는 것을 막기 위한 것이다 —
    상세는 main._main의 워터마크 계산 주석 참조.

    rpd=None이면 파일에 있던 값을 그대로 남긴다 — 번역을 한 건도 하지 않고 끝나는
    실행(신규 CVE 없음)이 이전 실행의 사용량 기록을 지워버리면 안 되기 때문이다.

    반드시 기존 상태 위에 덮어쓴다(새 dict로 갈아끼우지 않는다). 예전에는 payload를
    새로 만들어 저장해서, 백필이 남긴 force_full_export 표시를 다음 매시간 실행이
    통째로 지워버렸다 — 그래서 백필을 몇 번 돌려도 대시보드에 반영되지 않았다.
    이 테이블은 워터마크 말고도 다른 소비자가 쓰는 공유 상태다."""
    payload = _read_state()
    payload["last_processed_until"] = dt_utc.astimezone(pytz.UTC).isoformat()
    # 빈 값은 키를 지운다 — 병합이라고 해서 해소된 격리·실패가 남으면 안 된다
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
    """번역 백필의 회전 스캔 위치. 없으면 0.

    한 실행이 볼 수 있는 창은 수백 건인데 추적 행은 만 건대라, 창을 늘 앞에서 잡으면
    뒤쪽은 영원히 못 본다. 위치를 실행 간에 이어붙여 전체를 한 바퀴 돌게 한다."""
    v = _read_state().get("translation_scan_offset")
    return v if isinstance(v, int) and v >= 0 else 0


def write_backfill_offset(offset: int) -> None:
    """회전 스캔 위치 저장 (워터마크·격리 상태는 건드리지 않음)."""
    data = _read_state()
    data["translation_scan_offset"] = max(0, int(offset))
    _write_state(data)


def write_rpd_state(rpd: Dict[str, Dict[str, int]]) -> None:
    """RPD 버킷만 갱신한다 (워터마크·격리 상태는 건드리지 않음).

    번역 백필처럼 워터마크 저장 이후에 소비되는 호출까지 사용량에 반영하기 위한 것."""
    data = _read_state()
    if rpd:
        data["rpd"] = rpd
    else:
        data.pop("rpd", None)
    _write_state(data)
