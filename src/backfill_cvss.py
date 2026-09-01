from __future__ import annotations

import argparse
import os
import re
import sys
import time
from typing import Dict, List, Tuple

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

import requests

import feed
import risk
from collector import collect_cvss, pick_cvss
from database import ArgusDB
from logger import logger

_VER = re.compile(r"CVSS:(\d\.\d)")
_LOG_SAMPLE = 30

_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD 는 미국 정부 저작물이라 퍼블릭 도메인이고 무료다. 이 저장소가 이미
# backfill_vendors·backfill_published 에서 쓰고 있어 새로 붙는 의존성도 없다.
# 키 없으면 30초에 5요청, 키가 있으면 50요청 — 574건이면 76분 vs 7분이다.
_GAP_KEY, _GAP_NO_KEY = 0.7, 8.0
_NVD_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))
_NVD_FAIL_STOP = 5


def version_of(vector) -> str:
    m = _VER.match(str(vector or "").strip())
    return m.group(1) if m else ""


def containers_of(record: Dict) -> List[Dict]:
    c = (record or {}).get("containers") or {}
    out = [c.get("cna") or {}]
    adp = c.get("adp")
    if isinstance(adp, list):
        out.extend(x for x in adp if isinstance(x, dict))
    return out


def nvd_cvss(cve_id: str, api_key: str = "", timeout: int = 60) -> Dict:
    """NVD 가 가진 CVSS 를 collect_cvss 와 같은 모양으로 — {"3.0": (7.5, "CVSS:3.0/…")}.

    2016년 이전 CVE 는 구형 CVE 포맷에서 cvelistV5 로 일괄 변환된 것이라 metrics 블록이
    아예 없다 — 실측으로 화면의 N/A 574건 중 **572건**이 그렇다. 버전을 하나만 읽고
    끊던 버그와는 다른 문제라서, 소스를 하나 더 봐야 고칠 수 있다.

    **CVSS 2.0 은 3.x/4.0 이 하나도 없을 때만 쓴다.** 산식도 척도도 달라서 둘을 한
    max 에 넣고 비교하면 안 된다(CVE-2016-0736: v2=5.0 · v3.0=7.5). 대신 어느 버전인지
    화면·리포트·Slack 에 이미 적고 있으므로, "5.0 (v2.0)"은 정직하게 읽힌다.
    실측(표본 25건): 3.x/4.0 이 있는 것 16% · **2.0 만 있는 것 84%** · 둘 다 없는 것 0%.
    2.0 을 버리면 관측된 악용(T0) 480여 건이 심각도 칸을 계속 비워 둔다.
    """
    try:
        resp = requests.get(_NVD, params={"cveId": cve_id},
                            headers={"apiKey": api_key} if api_key else {}, timeout=timeout)
        resp.raise_for_status()
        vulns = (resp.json() or {}).get("vulnerabilities") or []
    except (requests.exceptions.RequestException, ValueError) as e:
        raise RuntimeError(f"NVD 조회 실패: {e}") from e
    if not vulns:
        return {}

    metrics = ((vulns[0].get("cve") or {}).get("metrics") or {})
    found: Dict[str, Tuple[float, str]] = {}
    for key, label in _NVD_KEYS:
        for entry in metrics.get(key) or []:
            data = (entry or {}).get("cvssData") or {}
            score = data.get("baseScore")
            if score is None:
                continue
            try:
                score = float(score)
            except (TypeError, ValueError):
                continue
            prev = found.get(label)
            if prev is None or prev[0] < score:
                found[label] = (score, data.get("vectorString") or "N/A")
    if found:
        return found

    for entry in metrics.get("cvssMetricV2") or []:
        data = (entry or {}).get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        try:
            score = float(score)
        except (TypeError, ValueError):
            continue
        prev = found.get("2.0")
        if prev is None or prev[0] < score:
            # v2 벡터는 PR 대신 Au 를 쓴다 → risk.is_remote_unauth 가 False 를 돌려주므로
            # cvss_critical_remote 가 켜질 수 없다. 점수만 채우고 판정은 안 건드린다.
            found["2.0"] = (score, data.get("vectorString") or "N/A")
    return found


def recompute(state: Dict, record: Dict) -> Dict:
    """cvelistV5 레코드로 CVSS 를 다시 읽는다."""
    return apply_scores(state, collect_cvss(containers_of(record)))


def apply_scores(state: Dict, found: Dict) -> Dict:
    """저장된 state 에서 CVSS 4개 키와 tier 만 갈아 끼운 새 state.

    이 함수는 점수를 **내리지 않는다.** 소급 도구의 일은 "옛 코드가 버린 버전을 되찾는
    것"이지 레코드를 다시 동기화하는 게 아니다. 진짜로 하향 수정된 CVE 는 delta 피드가
    정상 경로로 고쳐 준다. 여기서 낮추면 그 둘을 구별할 수 없다.

    점수가 그대로여도 항상 새 state 를 돌려준다 — cvss_version 키를 심어야 다음 실행에서
    같은 행을 다시 붙잡지 않는다. 그 키의 유무가 곧 대상 선정 기준이다.
    """
    found = dict(found)
    old_score = float(state.get("cvss") or 0.0)
    old_vector = state.get("cvss_vector") or "N/A"
    old_ver = version_of(old_vector)

    if old_score > 0 and old_ver:
        prev = found.get(old_ver)
        if prev is None or float(prev[0]) < old_score:
            found[old_ver] = (old_score, old_vector)

    score, vector, ver = pick_cvss(found)
    if score < old_score:
        # 버전을 알 수 없는 옛 점수(NVD 보충분 등)가 더 높다 → 숫자는 그대로 두고
        # 찾은 것만 병기한다. cvss_version 키가 생기므로 다음 실행에서 다시 안 잡힌다.
        score, vector, ver = old_score, old_vector, old_ver

    new = dict(state)
    new["cvss"] = score
    new["cvss_vector"] = vector
    new["cvss_version"] = ver
    new["cvss_scores"] = {k: [v[0], v[1]] for k, v in found.items()}
    # 티어는 저장된 state 그대로에서 다시 센다 — KEV·EPSS·PoC 를 다시 받아오지 않으므로
    # 어떤 신호도 잃을 수 없다. CVSS 가 건드리는 트리거는 cvss_critical_remote 와
    # unscored_major_cna 둘뿐이고 둘 다 T2 라, 이 도구가 알림 트리거를 새로 켜는 일은
    # 구조적으로 불가능하다 (tests/test_backfill_cvss.py 가 이걸 지킨다).
    new["tier"] = risk.evaluate(new).tier
    return new


def _priority(row: Dict) -> Tuple[int, int, str]:
    state = row.get("last_alert_state") or {}
    # 화면에 N/A 로 떠 있는 것(점수 0)이 사용자가 실제로 본 증상이다. 그 다음이 알림
    # 등급 순 — 한 회차 상한에 걸려도 중요한 것부터 고쳐진다.
    return (risk.tier_rank(str(state.get("tier") or risk.T3)),
            0 if float(state.get("cvss") or 0.0) <= 0.0 else 1,
            str(row.get("id") or ""))


def _fill_from_nvd(results: List[Tuple[str, Dict, Dict]],
                   budget: float) -> Tuple[int, int, int]:
    """cvelistV5 로 못 채운 행을 NVD 로 한 번 더 본다. (채운 수, 그중 v2, 실패 수)

    cvelistV5 에 metrics 가 아예 없는 옛 CVE 를 위한 경로다. 화면의 N/A 574건 중
    **572건**이 여기 해당하고, 그중 571건이 T0(관측된 악용)다 — 시스템이 존재하는 이유인
    행들이 심각도 칸을 비워 두고 있었다.
    """
    todo = [(cid, new) for cid, _, new in results if float(new.get("cvss") or 0.0) <= 0.0]
    if not todo:
        return 0, 0, 0

    api_key = os.environ.get("NVD_API_KEY", "")
    gap = _GAP_KEY if api_key else _GAP_NO_KEY
    logger.info(f"cvelistV5 에 점수가 없는 {len(todo):,}건 → NVD 조회 "
                f"(키 {'있음' if api_key else '없음'} · 건당 {gap}초 · "
                f"예상 {len(todo) * gap / 60:.0f}분 · 예산 {budget / 60:.0f}분)")

    started = time.time()
    fixed = v2_only = failed = streak = 0
    for i, (cve_id, new) in enumerate(todo):
        if time.time() - started > budget:
            logger.info(f"  시간 예산 소진 — {len(todo) - i:,}건은 다음 실행에서 이어서 본다")
            break
        try:
            found = nvd_cvss(cve_id, api_key)
            streak = 0
        except RuntimeError as e:
            failed += 1
            streak += 1
            logger.warning(f"  {cve_id} {e}")
            if streak >= _NVD_FAIL_STOP:
                logger.warning(f"  연속 {streak}회 실패 — NVD 조회를 중단한다 "
                               f"(레이트리밋일 가능성. 남은 {len(todo) - i - 1:,}건은 다음 실행)")
                break
            time.sleep(gap)
            continue

        if found:
            new.update(apply_scores(new, found))
            fixed += 1
            if set(found) == {"2.0"}:
                v2_only += 1
        if i < len(todo) - 1:
            time.sleep(gap)

    logger.info(f"NVD 보충 {fixed:,}/{len(todo):,}건 "
                f"(그중 CVSS 2.0 만 있는 것 {v2_only:,}건 — 버전을 함께 표기한다)"
                + (f" · 조회 실패 {failed:,}건" if failed else ""))
    return fixed, v2_only, failed


def run(limit: int, dry_run: bool, workers: int = 24, nvd_budget: float = 2400.0) -> int:
    started = time.time()
    db = ArgusDB()

    rows = db.get_rows_needing_cvss()
    if not rows:
        logger.info("✅ 손볼 행이 없다 — 모두 버전이 있고 점수도 있다")
        return 0

    rows.sort(key=_priority)
    unscored = sum(1 for r in rows
                   if float((r.get("last_alert_state") or {}).get("cvss") or 0.0) <= 0.0)
    logger.info(f"대상 {len(rows):,}건 "
                f"(화면에 N/A 로 떠 있는 {unscored:,}건 먼저)")

    targets = rows[:limit]
    if len(rows) > limit:
        logger.info(f"이번 실행은 {limit:,}건까지만 — 나머지 {len(rows) - limit:,}건은 "
                    f"다시 돌리면 이어서 처리한다")

    # dry-run 도 레코드는 받아서 전부 계산한다. 저장만 하지 않는다 — 건수만 세는
    # 예행연습은 "얼마나 올라가는지 · 등급이 어디로 움직이는지"를 못 알려준다.
    changes = [feed.Change(cve_id=r["id"], batch_at=None) for r in targets if r.get("id")]
    feed.fill_records(changes, workers=workers)
    by_id = {c.cve_id: c.record for c in changes}

    results: List[Tuple[str, Dict, Dict]] = []   # (id, 원래 state, 새 state)
    no_record = 0

    for row in targets:
        cve_id = row.get("id")
        state = row.get("last_alert_state")
        record = by_id.get(cve_id)
        if not cve_id or not state:
            continue
        if record is None:
            no_record += 1
            continue
        try:
            results.append((cve_id, state, recompute(state, record)))
        except Exception as e:
            logger.warning(f"  {cve_id} 재계산 실패: {e}")

    nvd_fixed, nvd_v2, nvd_fail = _fill_from_nvd(results, nvd_budget)

    updates: List[Dict] = []
    raised, confirmed = 0, 0
    tier_moves: Dict[str, int] = {}
    for cve_id, state, new in results:
        old_score = float(state.get("cvss") or 0.0)
        if new["cvss"] > old_score:
            raised += 1
            if raised <= _LOG_SAMPLE:
                logger.info(f"  {cve_id} {old_score} → {new['cvss']} "
                            f"(v{new['cvss_version'] or '?'})")
            elif raised == _LOG_SAMPLE + 1:
                logger.info("  … 이하 생략 (상향 건수는 아래 요약에)")
        else:
            confirmed += 1

        before, after = str(state.get("tier") or risk.T3), new["tier"]
        if before != after:
            tier_moves[f"{before}→{after}"] = tier_moves.get(f"{before}→{after}", 0) + 1

        updates.append({
            "id": cve_id,
            "cvss_score": new["cvss"],
            "last_alert_state": new,
        })

    if dry_run:
        ok = 0
    else:
        # updated_at 은 일부러 건드리지 않는다 — 보존 기간이 그 값으로 나이를 세므로,
        # 여기서 갱신하면 1만 건의 나이가 한꺼번에 초기화돼 만료 정리가 무력해진다.
        ok = db.bulk_save_states(updates, "CVSS")
        if ok:
            db.request_full_export()

    still_na = sum(1 for _, _, new in results if float(new.get("cvss") or 0.0) <= 0.0)

    logger.info("=" * 60)
    logger.info(f"CVSS 소급{' 예행연습' if dry_run else ' 완료'}: 점수 상향 {raised:,} "
                f"(그중 NVD 보충 {nvd_fixed:,}) · 버전만 확인 {confirmed:,} · "
                + (f"저장 대상 {len(updates):,}건 (저장 안 함)" if dry_run
                   else f"저장 {ok:,}/{len(updates):,}건"))
    if nvd_v2:
        logger.info(f"  CVSS 2.0 으로 채운 것 {nvd_v2:,}건 — 3.x/4.0 이 어디에도 없는 옛 CVE 다. "
                    f"화면에 v2.0 이라고 함께 적힌다")
    if still_na:
        logger.warning(f"여전히 N/A {still_na:,}건 — cvelistV5 에도 NVD 에도 점수가 없다"
                       + (f" (조회 실패 {nvd_fail:,}건 포함, 다음 실행이 다시 본다)"
                          if nvd_fail else ""))
    if tier_moves:
        logger.info("등급 이동: " + " · ".join(f"{k} {v:,}" for k, v in sorted(tier_moves.items())))
        logger.info("  (점수를 찾으면 '점수 미부여 — 재평가 대기'(T2) 사유가 사라진다. "
                    "T3 로 내려가는 건 정상이다)")
    if no_record:
        logger.warning(f"레코드를 받지 못한 {no_record:,}건은 다음 실행에서 재시도")
    if len(rows) > len(targets):
        logger.info(f"남은 대상 {len(rows) - len(targets):,}건 — 다시 실행하면 이어서 처리")
    logger.info("Slack 알림 없음 · last_alert_at 미기록 — 이 도구는 notifier 를 부르지 않는다")
    logger.info(f"소요 {time.time() - started:.1f}초")
    logger.info("=" * 60)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="CVSS 가 낮거나 N/A 로 남은 행을 cvelistV5 재판독 + NVD 로 소급 보정")
    ap.add_argument("--limit", type=int,
                    default=int(os.environ.get("BACKFILL_CVSS_LIMIT", "1500")),
                    help="한 실행에서 처리할 최대 건수 (기본 1500)")
    ap.add_argument("--nvd-budget", type=float,
                    default=float(os.environ.get("BACKFILL_CVSS_NVD_BUDGET", "2400")),
                    help="NVD 조회에 쓸 최대 시간(초). 잡 타임아웃 60분 안에 들도록 "
                         "기본 2400초 — 넘으면 남은 건 다음 실행이 이어서 본다")
    ap.add_argument("--dry-run", action="store_true",
                    help="전부 계산만 하고 저장하지 않는다")
    args = ap.parse_args()
    try:
        return run(args.limit, args.dry_run, nvd_budget=args.nvd_budget)
    except Exception as e:
        logger.error(f"CVSS 소급 실패: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
