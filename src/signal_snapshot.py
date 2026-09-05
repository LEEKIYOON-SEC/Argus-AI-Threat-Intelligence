from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
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
    load: Callable[[], Optional[Set[str]]]


_RANSOM_SUFFIX = "#ransomware"


def cve_of(token: str) -> str:
    return token.split("#", 1)[0]


def _kev_ids() -> Optional[Set[str]]:
    data = enrichment_sources.load_cisa_kev()
    if data is None:
        return None
    out: Set[str] = set()
    for cve_id, item in data.items():
        out.add(cve_id)
        if str(item.get("knownRansomwareCampaignUse", "")).strip().lower() == "known":
            out.add(cve_id + _RANSOM_SUFFIX)
    return out


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
        Source("cisa_kev_v2", "CISA KEV", True, _kev_ids),
        Source("vulncheck_kev", "VulnCheck KEV", True, _vulncheck_ids),
        Source("nuclei", "nuclei 템플릿", False, _nuclei_ids),
        Source("metasploit", "Metasploit 모듈", False, _metasploit_ids),
        Source("exploitdb", "Exploit-DB", False, _exploitdb_ids),
        Source("epss_critical", f"EPSS p{risk.EPSS_P_CRITICAL:.0%}", False,
               _epss_critical_ids),
        Source("anthropic_cvd", "Anthropic CVD (ANT)", False,
               _anthropic_cvd_ids),
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
    known: Set[str] = field(default_factory=set)


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
        return Diff(source=source, added=[])

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
    return Diff(source=source, added=picked, known=known)


def commit(store, diff: Diff, processed: List[str]) -> None:
    if not processed:
        return
    if not diff.known:
        logger.error(f"[{diff.source.label}] 직전 집합이 비어 있다 — 스냅샷을 갱신하지 않는다 "
                     f"(축소 저장은 다음 회차 알림 폭풍이 된다)")
        return
    merged = diff.known | set(processed)
    if not store.save_snapshot(diff.source.key, digest_of(merged), merged):
        logger.error(f"[{diff.source.label}] 스냅샷 저장 실패 — 다음 회차가 다시 처리한다")
        return
    logger.info(f"[{diff.source.label}] 스냅샷 갱신: {len(diff.known):,} → {len(merged):,}건")
