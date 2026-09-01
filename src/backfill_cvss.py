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

import feed
import risk
from collector import collect_cvss, pick_cvss
from database import ArgusDB
from logger import logger

_VER = re.compile(r"CVSS:(\d\.\d)")
_LOG_SAMPLE = 30


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


def recompute(state: Dict, record: Dict) -> Dict:
    """저장된 state 에서 CVSS 4개 키와 tier 만 갈아 끼운 새 state.

    이 함수는 점수를 **내리지 않는다.** 소급 도구의 일은 "옛 코드가 버린 버전을 되찾는
    것"이지 레코드를 다시 동기화하는 게 아니다. 진짜로 하향 수정된 CVE 는 delta 피드가
    정상 경로로 고쳐 준다. 여기서 낮추면 그 둘을 구별할 수 없다.

    점수가 그대로여도 항상 새 state 를 돌려준다 — cvss_version 키를 심어야 다음 실행에서
    같은 행을 다시 붙잡지 않는다. 그 키의 유무가 곧 대상 선정 기준이다.
    """
    found = collect_cvss(containers_of(record))
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


def run(limit: int, dry_run: bool, workers: int = 24) -> int:
    started = time.time()
    db = ArgusDB()

    rows = db.get_rows_missing_cvss_version()
    if not rows:
        logger.info("✅ 모든 행이 이미 CVSS 버전을 갖고 있다 — 할 일 없음")
        return 0

    rows.sort(key=_priority)
    unscored = sum(1 for r in rows
                   if float((r.get("last_alert_state") or {}).get("cvss") or 0.0) <= 0.0)
    logger.info(f"버전 정보가 없는 행 {len(rows):,}건 "
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

    updates: List[Dict] = []
    raised, confirmed, no_record = 0, 0, 0
    tier_moves: Dict[str, int] = {}

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
            new = recompute(state, record)
        except Exception as e:
            logger.warning(f"  {cve_id} 재계산 실패: {e}")
            continue

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

    logger.info("=" * 60)
    logger.info(f"CVSS 소급{' 예행연습' if dry_run else ' 완료'}: 점수 상향 {raised:,} · "
                f"버전만 확인 {confirmed:,} · "
                + (f"저장 대상 {len(updates):,}건 (저장 안 함)" if dry_run
                   else f"저장 {ok:,}/{len(updates):,}건"))
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
        description="옛 코드가 CVSS 를 한 버전만 읽고 끊어서 낮거나 N/A 로 남은 행을 소급 보정")
    ap.add_argument("--limit", type=int,
                    default=int(os.environ.get("BACKFILL_CVSS_LIMIT", "1500")),
                    help="한 실행에서 처리할 최대 건수 (기본 1500)")
    ap.add_argument("--dry-run", action="store_true",
                    help="대상 건수만 확인하고 저장하지 않는다")
    args = ap.parse_args()
    try:
        return run(args.limit, args.dry_run)
    except Exception as e:
        logger.error(f"CVSS 소급 실패: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
