from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set

import ai_provenance
import enrichment_sources
import risk
from logger import logger

DEFAULT_CAP = 80


@dataclass(frozen=True)
class Source:
    key: str
    label: str
    fast: bool
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
    return set(idx) or None


def _metasploit_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_metasploit_index()
    return set(idx) or None


def _exploitdb_ids() -> Optional[Set[str]]:
    idx = enrichment_sources.load_exploitdb_index()
    return set(idx) or None


def _epss_critical_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_epss_full()
    if not data:
        return None
    return {cve for cve, (_score, pct) in data.items() if pct >= risk.EPSS_P_CRITICAL}


def _anthropic_cvd_ids() -> Optional[Set[str]]:
    data = ai_provenance.load_anthropic_ledger()
    return None if data is None else (set(data) or None)


SOURCES: Dict[str, Source] = {
    s.key: s for s in (
        Source("cisa_kev", "CISA KEV", True, "kev", _kev_ids),
        Source("vulncheck_kev", "VulnCheck KEV", True, "vulncheck_kev", _vulncheck_ids),
        Source("nuclei", "nuclei 템플릿", False, "nuclei", _nuclei_ids),
        Source("metasploit", "Metasploit 모듈", False, "metasploit", _metasploit_ids),
        Source("exploitdb", "Exploit-DB", False, "exploitdb", _exploitdb_ids),
        Source("epss_critical", f"EPSS p{risk.EPSS_P_CRITICAL:.0%}", False,
               "epss_critical", _epss_critical_ids),
        Source("anthropic_cvd", "Anthropic CVD (ANT)", False,
               "ai_discovered", _anthropic_cvd_ids),
    )
}


def digest_of(ids: Set[str]) -> str:
    h = hashlib.sha256()
    for cve in sorted(ids):
        h.update(cve.encode())
        h.update(b"\n")
    return h.hexdigest()


@dataclass
class Diff:
    source: Source
    added: List[str]
    total_added: int
    bootstrapped: bool = False


def sweep(store, fast_only: bool = False, cap: int = DEFAULT_CAP,
          only: Optional[List[str]] = None) -> List[Diff]:
    results: List[Diff] = []
    for key, source in SOURCES.items():
        if only is not None and key not in only:
            continue
        if fast_only and not source.fast:
            continue
        try:
            diff = _sweep_one(store, source, cap)
        except Exception as e:
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
        store.save_snapshot(source.key, new_digest, upstream)
        logger.info(f"[{source.label}] 스냅샷 최초 기록 {len(upstream):,}건 — 알림 없음")
        return Diff(source=source, added=[], total_added=0, bootstrapped=True)

    if stored_digest == new_digest:
        logger.debug(f"[{source.label}] 변화 없음 (digest 일치)")
        return None

    known = store.get_snapshot_ids(source.key)
    if not known:
        logger.warning(f"[{source.label}] 저장된 집합을 읽지 못함 → 이번 회차 생략")
        return None

    added = sorted(upstream - known)
    if not added:
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
    if not processed:
        return
    known = store.get_snapshot_ids(diff.source.key)
    merged = known | set(processed)
    store.save_snapshot(diff.source.key, digest_of(merged), merged)
    logger.info(f"[{diff.source.label}] 스냅샷 갱신: {len(known):,} → {len(merged):,}건")


class MemoryStore:
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
