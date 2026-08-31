"""cvelistV5 변경분 수집 — '무엇이 바뀌었는지'를 알아내는 자리.

예전에는 GitHub 커밋 API를 순회했다: 커밋 목록을 최대 300페이지까지 넘기고, 커밋마다
상세를 다시 불러(파일 300개씩 또 페이지네이션) 파일명에서 CVE를 긁고, 그 CVE마다
원문을 받아 해시를 비교했다. 변경분을 '발견'하는 데만 수백 번의 API 호출이 들었고,
토큰당 5,000/h 한도에 눌려 대기가 붙었으며, 그 시간이 알림 지연으로 그대로 넘어갔다.

CVE Program이 같은 정보를 이미 정리해서 내보낸다.

  ① cves/deltaLog.json — 배치별 변경 목록(최신순, 30일치 24MB).
     **무엇이 바뀌었는가의 유일한 기준.** Range 요청으로 앞부분만 받으면 되고
     (raw.githubusercontent가 Accept-Ranges: bytes를 준다) 보통 256KB면 몇 시간을 덮는다.

  ② 일별 delta ZIP — `cve_YYYY-MM-DD_HHMMZ` 태그의 `..._delta_CVEs_at_HHMMZ.zip`.
     **레코드 원문이 통째로** 들어 있어, 긴 공백을 메울 때 CVE마다 원문을 따로 받지
     않아도 된다. 변경 목록으로는 쓰지 않고 원문 공급원으로만 쓴다(아래 주의 참조).

둘 다 인증이 필요 없고 API 한도를 쓰지 않는다.

━━ 실측으로 확인한 두 가지 함정 ━━

**하나. 워터마크는 배치의 fetchTime으로 잡아야 한다.**
항목의 dateUpdated로 거르면 안 된다. 레코드가 뒤늦게 다시 밀려나오는 경우가 있어,
배치 시각보다 dateUpdated가 뒤처진 항목이 **6.4%**(30일 79,897건 실측, 최대 6.7시간)나
된다. dateUpdated 기준으로 자르면 그만큼이 조용히 사라진다 — 누락 0 원칙 위반이다.
그래서 '배치 단위로 소비'하고, dateUpdated는 표시용으로만 쓴다.

**둘. delta ZIP은 시간별이 아니라 그날 자정부터의 누적이다.**
19Z ZIP(110건) ⊂ 23Z ZIP(125건)이고 00Z에 빈 파일로 리셋된다(실측 확인). 그래서
'시간 슬롯마다 하나씩' 받으면 같은 내용을 몇 번씩 받게 된다. **하루에 하나만** 받는다.
(참고 물량: 평일 2,000~2,400건/일, 최대 5,542건/일, 일요일 133건/일)

출처: CVE Program (cvelistV5) — CC0 1.0
"""
from __future__ import annotations

import datetime
import io
import json
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import pytz
import requests

from logger import logger

_RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
_DELTA_LOG = f"{_RAW_BASE}/cves/deltaLog.json"
_RELEASE_BASE = "https://github.com/CVEProject/cvelistV5/releases/download"
_UA = {"User-Agent": "argus-feed"}

#: deltaLog 앞부분을 얼마씩 받아 볼지. 구간을 덮을 때까지 넓혀 간다.
#: (배치당 평균 ~15KB → 256KB면 대략 15~20배치. 마지막은 전량 24MB.)
_RANGE_STEPS: Tuple[Optional[int], ...] = (256 * 1024, 1024 * 1024, 4 * 1024 * 1024, None)

#: 공백이 이보다 길면 일별 ZIP으로 레코드 원문을 미리 채운다(개별 fetch 폭증 방지).
BULK_PREFILL_HOURS = 3
#: 한 실행이 따라잡을 최대 구간. 나머지는 전진된 워터마크에서 다음 실행이 이어받는다.
CATCHUP_MAX_HOURS = 24
#: 워터마크가 아예 없을 때(최초 실행) 소급할 기간
BOOTSTRAP_HOURS = 2
#: deltaLog가 보관하는 기간. 이보다 오래된 워터마크는 복구할 수 없다.
DELTA_LOG_RETENTION_DAYS = 30

_TIMEOUT = 90


@dataclass
class Change:
    """변경된 CVE 한 건."""
    cve_id: str
    #: 이 변경을 실은 배치의 시각. 워터마크 계산은 **반드시 이 값**을 쓴다.
    batch_at: datetime.datetime
    #: 레코드가 스스로 밝힌 최종 수정 시각(표시용). 배치보다 뒤처질 수 있다.
    updated_at: Optional[datetime.datetime] = None
    #: 신규 발행인가(= deltaLog의 "new" 버킷)
    is_new: bool = False
    #: ZIP으로 미리 채웠으면 원문이 들어 있다. 없으면 fill_records가 개별로 받는다.
    record: Optional[dict] = field(default=None, repr=False)


def _utc(dt: datetime.datetime) -> datetime.datetime:
    return dt.astimezone(pytz.UTC) if dt.tzinfo else pytz.UTC.localize(dt)


def _parse_ts(value) -> Optional[datetime.datetime]:
    try:
        return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


# ──────────────────────────────────────────────────────────────────────────
# ① deltaLog — 변경 목록의 유일한 기준
# ──────────────────────────────────────────────────────────────────────────
def _parse_array_prefix(text: str) -> List[dict]:
    """잘린 JSON 배열의 앞부분에서 **완성된 객체만** 뽑는다.

    Range로 받으면 마지막 객체는 반드시 도중에 끊긴다. 통째로 json.loads하면 그 하나
    때문에 전부 버리게 되므로, 객체 단위로 훑다가 실패하는 지점에서 멈춘다."""
    decoder = json.JSONDecoder()
    idx = text.find("[")
    if idx < 0:
        return []
    idx += 1
    out: List[dict] = []
    n = len(text)
    while idx < n:
        while idx < n and text[idx] in " \t\r\n,":
            idx += 1
        if idx >= n or text[idx] == "]":
            break
        try:
            obj, idx = decoder.raw_decode(text, idx)
        except ValueError:
            break          # 여기서부터는 잘린 꼬리
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _fetch_delta_log(nbytes: Optional[int]) -> List[dict]:
    """deltaLog.json 앞부분(nbytes)을 배치 목록으로. nbytes=None이면 전량."""
    headers = dict(_UA)
    if nbytes is not None:
        headers["Range"] = f"bytes=0-{nbytes - 1}"
    resp = requests.get(_DELTA_LOG, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()
    # 서버가 Range를 무시하고 200으로 전량을 줘도 파싱 결과는 같다
    return _parse_array_prefix(resp.content.decode("utf-8", errors="ignore"))


def _load_batches(since: datetime.datetime) -> Tuple[List[dict], bool]:
    """since를 덮는 배치 목록. (배치들, 구간을 완전히 덮었는가).

    앞부분부터 조금씩 받다가, 받아온 것 중 가장 오래된 배치가 since보다 과거가 되면
    구간을 덮은 것이다. 전량(24MB)까지 가도 못 덮으면 워터마크가 deltaLog 보관기간
    밖이라는 뜻이라 False를 돌려준다."""
    for step in _RANGE_STEPS:
        label = "전량" if step is None else f"{step // 1024}KB"
        try:
            batches = _fetch_delta_log(step)
        except requests.exceptions.RequestException as e:
            logger.warning(f"deltaLog {label} 수신 실패: {e}")
            continue
        stamps = [t for t in (_parse_ts(b.get("fetchTime")) for b in batches) if t]
        if not stamps:
            continue
        if min(stamps) <= since or step is None:
            covered = min(stamps) <= since
            logger.info(f"📥 deltaLog {label} · 배치 {len(batches)}건"
                        f"{'' if covered else ' (구간 미달)'}")
            return batches, covered
        logger.debug(f"deltaLog {label}로는 부족 (가장 오래된 배치 {min(stamps).isoformat()})")
    return [], False


def _collect(batches: List[dict], since: datetime.datetime,
             until: datetime.datetime) -> Tuple[List[Change], datetime.datetime]:
    """(since, until] 배치의 변경 CVE. 같은 CVE는 가장 최신 배치 하나로 접는다.

    거르는 기준은 **배치의 fetchTime**이다 (모듈 주석의 '함정 하나' 참조).
    """
    latest: Dict[str, Change] = {}
    # 신규 여부는 '이긴 배치'와 무관하게 따로 모은다. deltaLog는 최신순이라, 발행(new)
    # 배치보다 갱신(updated) 배치를 먼저 만나는 게 정상이다 — 이긴 쪽에만 표시를 두면
    # 창 안에서 발행되고 곧 갱신된 CVE가 '신규 아님'으로 뒤집힌다.
    born: set = set()
    horizon = since
    for batch in batches:
        batch_at = _parse_ts(batch.get("fetchTime"))
        if batch_at is None or batch_at <= since or batch_at > until:
            continue
        if batch_at > horizon:
            horizon = batch_at
        for key, is_new in (("new", True), ("updated", False)):
            for item in batch.get(key) or []:
                cve_id = item.get("cveId")
                if not cve_id:
                    continue
                if is_new:
                    born.add(cve_id)
                prev = latest.get(cve_id)
                if prev is not None and prev.batch_at >= batch_at:
                    continue
                latest[cve_id] = Change(
                    cve_id=cve_id,
                    batch_at=batch_at,
                    updated_at=_parse_ts(item.get("dateUpdated")),
                )
    for cve_id in born:
        if cve_id in latest:
            latest[cve_id].is_new = True
    changes = sorted(latest.values(), key=lambda c: c.batch_at)
    return changes, horizon


# ──────────────────────────────────────────────────────────────────────────
# ② 일별 delta ZIP — 레코드 원문 대량 공급 (변경 목록으로는 쓰지 않는다)
# ──────────────────────────────────────────────────────────────────────────
def _fetch_day_zip(day: datetime.date, newest_hour: int = 23) -> Dict[str, dict]:
    """그날의 누적 delta ZIP → {cve_id: record}.

    ZIP은 자정부터의 누적이라 하루에 **하나만** 받으면 된다. 가장 늦은 시각부터
    거슬러 올라가며 처음 성공하는 것을 쓴다(막 지난 시각은 아직 릴리스되지 않았을 수 있다).
    """
    for hour in range(newest_hour, -1, -1):
        tag = f"cve_{day:%Y-%m-%d}_{hour:02d}00Z"
        asset = f"{day:%Y-%m-%d}_delta_CVEs_at_{hour:02d}00Z.zip"
        try:
            resp = requests.get(f"{_RELEASE_BASE}/{tag}/{asset}",
                                timeout=_TIMEOUT, headers=_UA)
        except requests.exceptions.RequestException as e:
            logger.debug(f"delta ZIP {tag} 수신 실패: {e}")
            continue
        if resp.status_code != 200 or len(resp.content) < 100:
            continue          # 404이거나 리셋 직후의 빈 ZIP
        try:
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                out: Dict[str, dict] = {}
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    try:
                        record = json.loads(zf.read(name))
                    except (ValueError, KeyError):
                        continue
                    cve_id = (record.get("cveMetadata") or {}).get("cveId")
                    if cve_id:
                        out[cve_id] = record
            logger.info(f"📦 delta ZIP {day:%Y-%m-%d} {hour:02d}Z → 레코드 {len(out)}건")
            return out
        except zipfile.BadZipFile as e:
            logger.warning(f"delta ZIP {tag} 해제 실패: {e}")
    return {}


def prefill_records(changes: List[Change], since: datetime.datetime,
                    now: datetime.datetime) -> int:
    """공백이 길면 일별 ZIP으로 레코드 원문을 미리 채운다. 채운 건수 반환.

    개별 fetch를 줄이려는 최적화일 뿐이라, 실패해도 fill_records가 정상적으로 메운다."""
    if not changes:
        return 0
    span_h = (now - since).total_seconds() / 3600.0
    if span_h < BULK_PREFILL_HOURS:
        return 0

    pool: Dict[str, dict] = {}
    day = since.date()
    while day <= now.date():
        newest = now.hour if day == now.date() else 23
        pool.update(_fetch_day_zip(day, newest_hour=newest))
        day += datetime.timedelta(days=1)

    filled = 0
    for change in changes:
        if change.record is None and change.cve_id in pool:
            change.record = pool[change.cve_id]
            filled += 1
    if filled:
        logger.info(f"📦 ZIP으로 레코드 {filled}/{len(changes)}건 선충전 "
                    f"(개별 요청 그만큼 절약)")
    return filled


# ──────────────────────────────────────────────────────────────────────────
# 공개 API
# ──────────────────────────────────────────────────────────────────────────
def changes_since(since: Optional[datetime.datetime],
                  now: Optional[datetime.datetime] = None,
                  prefill: bool = True) -> Tuple[List[Change], datetime.datetime]:
    """워터마크 이후 변경된 CVE 목록과 '어디까지 덮었는지'(horizon)를 돌려준다.

    horizon은 **본 것의 끝**이다. 워터마크를 여기까지 바로 전진시키면 안 된다 —
    호출부가 처리 실패분의 배치 시각과 비교해 그보다 앞에서 멈춰야 누락이 없다.
    """
    now = _utc(now or datetime.datetime.now(pytz.UTC))
    if since is None:
        since = now - datetime.timedelta(hours=BOOTSTRAP_HOURS)
        logger.info(f"워터마크 없음 → 최근 {BOOTSTRAP_HOURS}h 부트스트랩")
    since = _utc(since)
    if since >= now:
        return [], now

    retention_floor = now - datetime.timedelta(days=DELTA_LOG_RETENTION_DAYS)
    if since < retention_floor:
        logger.error(f"⛔ 워터마크({since.isoformat()})가 deltaLog 보관기간"
                     f"({DELTA_LOG_RETENTION_DAYS}일) 밖 — {retention_floor.isoformat()}부터 재개")
        since = retention_floor

    # 한 실행의 조회 창 상한. 창 밖은 전진된 워터마크에서 다음 실행이 이어받는다.
    until = min(now, since + datetime.timedelta(hours=CATCHUP_MAX_HOURS))
    if until < now:
        logger.warning(f"공백 {(now - since).total_seconds() / 3600:.1f}h — 이번 실행은 "
                       f"{CATCHUP_MAX_HOURS}h까지만 따라잡는다 (나머지는 다음 실행)")

    batches, covered = _load_batches(since)
    if not batches:
        logger.warning("deltaLog를 읽지 못함 — 이번 실행은 워터마크를 전진시키지 않는다")
        return [], since
    if not covered:
        logger.error("⛔ deltaLog 전량으로도 구간을 못 덮음 — 그 앞 구간은 유실 가능")

    changes, horizon = _collect(batches, since, until)
    logger.info(f"변경 CVE {len(changes)}건 ({since:%m-%d %H:%M} → {horizon:%m-%d %H:%M} UTC)")
    if prefill:
        prefill_records(changes, since, now)
    return changes, horizon


def fetch_record(cve_id: str, timeout: int = 20) -> Optional[dict]:
    """CVE 레코드 원문 1건 (raw.githubusercontent — API 한도 미소모)."""
    parts = cve_id.split("-")
    if len(parts) < 3:
        return None
    year, num = parts[1], parts[2]
    group = "0xxx" if len(num) < 4 else num[:-3] + "xxx"
    url = f"{_RAW_BASE}/cves/{year}/{group}/{cve_id}.json"
    try:
        resp = requests.get(url, timeout=timeout, headers=_UA)
        if resp.status_code == 404:
            logger.warning(f"{cve_id}: 레코드 없음 (404)")
            return None
        resp.raise_for_status()
        return resp.json()
    except (requests.exceptions.RequestException, ValueError) as e:
        logger.debug(f"{cve_id} 레코드 수신 실패: {e}")
        return None


def fill_records(changes: List[Change], workers: int = 8) -> List[Change]:
    """record가 비어 있는 Change에 레코드 원문을 채운다 (병렬).

    받지 못한 건은 record=None으로 남는다 — 호출부가 failed로 처리해 워터마크가 붙잡고
    다음 실행에서 다시 시도한다(누락 0)."""
    pending = [c for c in changes if c.record is None]
    if not pending:
        return changes
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for change, record in zip(pending, ex.map(lambda c: fetch_record(c.cve_id), pending)):
            change.record = record
    missing = sum(1 for c in pending if c.record is None)
    logger.info(f"레코드 개별 수신 {len(pending) - missing}/{len(pending)}건"
                + (f" · 실패 {missing}건은 다음 실행 재시도" if missing else ""))
    return changes
