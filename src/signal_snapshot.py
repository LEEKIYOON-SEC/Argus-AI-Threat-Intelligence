"""소스측 스냅샷 대조 — '저위험을 쌓아두지 않아도 에스컬레이션을 놓치지 않는' 장치.

━━ 왜 방향을 뒤집었나 ━━

예전 구조는 DB에서 후보를 골라 재평가했다(check_for_escalations). 그 조회 조건이
`최근 30일 · 300건 · is_kev=false`였는데, **선정 조건이 그대로 사각지대**가 된다.
2년 전 저위험 CVE에 오늘 Metasploit 모듈이 올라오면 그 창에 안 들어와 영영 못 봤다.
게다가 그 방식은 '저위험도 일단 DB에 넣어 둔다'를 전제하므로 행이 무한정 불어난다.

알림을 유발하는 신호는 전부 **소스 쪽에서 전량 열거**가 된다. KEV 1,685건, VulnCheck
KEV, nuclei 4,363건, Metasploit 3,198건, ExploitDB, EPSS 366,357건 — 통째로 받을 수
있다. 그러면 "지난번 집합과 비교해 새로 들어온 것"이 곧 에스컬레이션이고, 우리 DB에
그 CVE가 있었는지는 아무 상관이 없다. 전 기간이 덮이고, 저위험 보관도 필요 없어진다.

━━ 비용을 어떻게 눌렀나 ━━

집합 전체를 매번 DB에서 읽으면 Supabase egress가 샌다(불변 원칙 2). 그래서 **digest
게이팅**을 둔다: 먼저 해시만 비교하고(수십 바이트), 다르면 그때만 집합을 읽는다.
업스트림이 실제로 바뀌는 건 대개 하루 한두 번이라 대부분의 실행은 해시 비교에서 끝난다.

━━ 안전 규칙 두 가지 ━━

**하나. 수신 실패를 빈 집합으로 취급하지 않는다.** 로더는 실패 시 None을 돌려주고,
None이면 그 소스는 통째로 건너뛴다. 빈 집합으로 저장해 버리면 다음 실행에서 전량이
'신규'로 보여 알림 폭풍이 난다.

**둘. 저장하는 집합은 합집합이다.** upstream이 아니라 `기존 ∪ 이번에 처리한 것`을
저장한다. 신호가 소스에서 빠졌다가 다시 들어와도(KEV 재등재, 템플릿 리네임) 재알림이
나가지 않는다 — 우리가 막으려던 반복 발화 그 자체이기 때문이다. 상한(cap)에 걸려 일부만
처리한 회차에서도, 남은 것이 다음 실행에 그대로 '신규'로 남아 이어서 처리된다.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set

import enrichment_sources
import risk
from logger import logger

#: 한 소스가 한 실행에서 새로 밀어 넣을 수 있는 CVE 수의 상한.
#: EPSS는 모델이 갱신되면(예: v2026.06.15) 수천 건이 한꺼번에 임계를 넘나든다 —
#: 그때 전부 레코드를 받으면 실행이 통째로 그 일에 잡아먹힌다. 나눠서 수렴시킨다.
DEFAULT_CAP = 80


# ──────────────────────────────────────────────────────────────────────────
# 소스 정의
# ──────────────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class Source:
    key: str
    label: str
    #: fast-lane(5분)에서 돌릴 만큼 가벼운가. 무거운 것은 bulk-lane(시간별)에서 돈다.
    fast: bool
    #: 이 소스가 켜는 risk 트리거 (로그·알림 사유 표기에 쓴다)
    trigger: str
    load: Callable[[], Optional[Set[str]]]


def _kev_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_cisa_kev()
    return None if data is None else set(data)


def _vulncheck_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_vulncheck_kev()
    return None if data is None else set(data)


def _nuclei_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_nuclei_index()
    return set(idx) or None       # 빈 결과는 수신 실패로 본다


def _metasploit_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_metasploit_index()
    return set(idx) or None


def _exploitdb_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_exploitdb_index()
    return set(idx) or None


def _epss_critical_ids() -> Optional[Set[str]]:
    """EPSS가 알림 임계(p99)를 넘은 CVE 전량. 임계는 risk.py가 소유한다."""
    data = enrichment_sources.load_epss_full()
    if not data:
        return None
    return {cve for cve, (_score, pct) in data.items() if pct >= risk.EPSS_P_CRITICAL}


#: fast=True 는 5분 주기에서도 부담 없는 것(수 KB~수백 KB).
#: ExploitDB·Metasploit·nuclei·EPSS는 수 MB라 시간별 bulk-lane에 둔다.
SOURCES: Dict[str, Source] = {
    s.key: s for s in (
        Source("cisa_kev", "CISA KEV", True, "kev", _kev_ids),
        Source("vulncheck_kev", "VulnCheck KEV", True, "vulncheck_kev", _vulncheck_ids),
        Source("nuclei", "nuclei 템플릿", False, "nuclei", _nuclei_ids),
        Source("metasploit", "Metasploit 모듈", False, "metasploit", _metasploit_ids),
        Source("exploitdb", "Exploit-DB", False, "exploitdb", _exploitdb_ids),
        Source("epss_critical", f"EPSS p{risk.EPSS_P_CRITICAL:.0%}", False,
               "epss_critical", _epss_critical_ids),
    )
}


def digest_of(ids: Set[str]) -> str:
    """집합의 지문. 정렬해서 해싱하므로 순서에 흔들리지 않는다."""
    h = hashlib.sha256()
    for cve in sorted(ids):
        h.update(cve.encode())
        h.update(b"\n")
    return h.hexdigest()


# ──────────────────────────────────────────────────────────────────────────
# 대조
# ──────────────────────────────────────────────────────────────────────────
@dataclass
class Diff:
    source: Source
    added: List[str]          # 이번 실행에서 처리할 신규 CVE (상한 적용 후)
    total_added: int          # 상한 적용 전 신규 건수
    bootstrapped: bool = False   # 최초 기록이라 알림 없이 저장만 했는가


def sweep(store, fast_only: bool = False, cap: int = DEFAULT_CAP,
          only: Optional[List[str]] = None) -> List[Diff]:
    """모든(또는 지정한) 소스를 대조해 새로 들어온 CVE를 돌려준다.

    store는 아래 세 메서드만 있으면 된다 (ArgusDB가 구현한다):
        get_snapshot_digest(source) -> Optional[str]
        get_snapshot_ids(source)    -> Set[str]
        save_snapshot(source, digest, ids) -> bool
    """
    results: List[Diff] = []
    for key, source in SOURCES.items():
        if only is not None and key not in only:
            continue
        if fast_only and not source.fast:
            continue
        try:
            diff = _sweep_one(store, source, cap)
        except Exception as e:
            # 한 소스의 장애가 나머지 대조를 막지 않게 격리한다
            logger.error(f"[{source.label}] 스냅샷 대조 실패: {e}")
            continue
        if diff is not None:
            results.append(diff)
    return results


def _sweep_one(store, source: Source, cap: int) -> Optional[Diff]:
    upstream = source.load()
    if upstream is None:
        logger.warning(f"[{source.label}] 수신 실패 → 이번 회차 대조 생략 "
                       f"(빈 집합으로 저장하지 않는다)")
        return None

    new_digest = digest_of(upstream)
    stored_digest = store.get_snapshot_digest(source.key)

    if stored_digest is None:
        # 최초 기록 — 지금 있는 전량을 '이미 아는 것'으로 저장하고 알림은 보내지 않는다.
        # 그러지 않으면 배포 첫 실행에서 KEV 1,685건이 통째로 알림으로 나간다.
        store.save_snapshot(source.key, new_digest, upstream)
        logger.info(f"[{source.label}] 스냅샷 최초 기록 {len(upstream):,}건 — 알림 없음")
        return Diff(source=source, added=[], total_added=0, bootstrapped=True)

    if stored_digest == new_digest:
        logger.debug(f"[{source.label}] 변화 없음 (digest 일치)")
        return None

    known = store.get_snapshot_ids(source.key)
    if not known:
        # digest는 있는데 집합을 못 읽었다 = 조회 실패. 저장을 건드리면 안 된다.
        logger.warning(f"[{source.label}] 저장된 집합을 읽지 못함 → 이번 회차 생략")
        return None

    added = sorted(upstream - known)
    if not added:
        # 빠지기만 했다 — 합집합 정책상 저장할 게 없다. digest만 맞춰 두면
        # 다음 실행이 매번 집합을 다시 읽는 낭비를 피할 수 있다.
        store.save_snapshot(source.key, digest_of(known | upstream), known | upstream)
        logger.info(f"[{source.label}] 신규 없음 (제외분만 변동)")
        return None

    picked = added[:cap]
    if len(added) > cap:
        logger.warning(f"[{source.label}] 신규 {len(added):,}건 중 {cap}건만 이번에 처리 "
                       f"— 나머지는 다음 실행이 이어받는다")
    logger.info(f"🚨 [{source.label}] 신규 {len(picked)}건: {picked[:5]}"
                f"{' …' if len(picked) > 5 else ''}")
    return Diff(source=source, added=picked, total_added=len(added))


def commit(store, diff: Diff, processed: List[str]) -> None:
    """실제로 처리를 마친 CVE만 '아는 것'에 더한다.

    처리 도중 죽거나 일부가 실패하면 그 CVE는 저장되지 않아 다음 실행에서 다시 신규로
    잡힌다 — 알림 유실보다 중복 시도가 낫다는 기존 원칙(누락 0)을 그대로 따른다."""
    if not processed:
        return
    known = store.get_snapshot_ids(diff.source.key)
    merged = known | set(processed)
    store.save_snapshot(diff.source.key, digest_of(merged), merged)
    logger.info(f"[{diff.source.label}] 스냅샷 갱신: {len(known):,} → {len(merged):,}건")


# ──────────────────────────────────────────────────────────────────────────
# 테스트/로컬용 인메모리 저장소
# ──────────────────────────────────────────────────────────────────────────
class MemoryStore:
    """자격증명 없이 도는 로컬 실행·테스트용. 프로세스가 끝나면 사라진다."""

    def __init__(self, initial: Optional[Dict[str, Set[str]]] = None):
        self._ids: Dict[str, Set[str]] = {k: set(v) for k, v in (initial or {}).items()}
        self._digest: Dict[str, str] = {k: digest_of(v) for k, v in self._ids.items()}

    def get_snapshot_digest(self, source: str) -> Optional[str]:
        return self._digest.get(source)

    def get_snapshot_ids(self, source: str) -> Set[str]:
        return set(self._ids.get(source, set()))

    def save_snapshot(self, source: str, digest: str, ids: Set[str]) -> bool:
        self._ids[source] = set(ids)
        self._digest[source] = digest
        return True

    def dump(self) -> str:
        return json.dumps({k: len(v) for k, v in self._ids.items()}, ensure_ascii=False)
