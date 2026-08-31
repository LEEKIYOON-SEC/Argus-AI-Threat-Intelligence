#!/usr/bin/env python3
"""오래된 CVE 리포트 이슈를 정리한다 — 트리아지 화면을 되돌리기 위한 1회성 도구.

Argus는 고위험 CVE마다 GitHub Issue로 상세 리포트를 발행해 왔고, 닫는 경로가 없었다.
그 결과 열린 이슈가 4,866건까지 쌓여 `label:kev`로 걸러도 목록이 화면을 넘어간다 —
'지금 봐야 하는 것'을 찾는 용도로는 이미 쓸 수 없는 상태다.

무엇을 닫는가:
  · 라벨 `cve`가 붙은 Argus 발행 이슈 중
  · KEV·무기화 라벨(`kev` / `exploited`)이 **없고**
  · N일(기본 180) 이상 갱신이 없는 것

닫아도 안전한 이유: 이슈는 '읽는 리포트'이지 대응 추적 도구가 아니다. 본문은 닫혀도
그대로 남아 사후 점검·감사에 쓸 수 있고, 그 CVE에 나중에 악용 신호가 붙으면 파이프라인이
소스측 대조로 다시 잡아 **새 알림**을 낸다(signal_snapshot). 닫는 것이 정보를 지우지 않는다.

  python3 tools/close_stale_issues.py                  # 어떤 것이 닫힐지만 본다(기본)
  python3 tools/close_stale_issues.py --apply          # 실제로 닫는다
  python3 tools/close_stale_issues.py --days 365 --apply
  python3 tools/close_stale_issues.py --keep-labels kev,exploited,poc --apply

표준 라이브러리만 쓴다(pip install 불필요) — tools/sbom_match.py와 같은 방침.
필요한 것은 issues:write 권한의 GH_TOKEN과 GITHUB_REPOSITORY뿐이다.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Iterator, List, Optional

_API = "https://api.github.com"
_UA = "argus-issue-cleanup"


def _request(url: str, token: str, method: str = "GET",
             payload: Optional[Dict] = None) -> tuple:
    """(상태코드, 본문, 헤더). 2차 레이트리밋은 호출부가 처리한다."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": _UA,
        **({"Content-Type": "application/json"} if data else {}),
    })
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode() or "null"), dict(resp.headers)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        return e.code, body, dict(e.headers or {})


def _sleep_for_ratelimit(headers: Dict, attempt: int) -> float:
    """GitHub이 알려준 재개 시각을 우선 따르고, 없으면 지수 백오프."""
    retry_after = headers.get("Retry-After")
    if retry_after:
        try:
            return float(retry_after)
        except ValueError:
            pass
    reset = headers.get("X-RateLimit-Reset")
    if reset:
        try:
            wait = float(reset) - time.time()
            if 0 < wait < 900:
                return wait + 1
        except ValueError:
            pass
    return min(2.0 ** attempt, 60.0)


def iter_open_issues(repo: str, token: str, label: str) -> Iterator[Dict]:
    """라벨이 붙은 열린 이슈를 전부 훑는다 (PR은 제외)."""
    page = 1
    while True:
        q = urllib.parse.urlencode({
            "state": "open", "labels": label, "per_page": 100,
            "page": page, "sort": "updated", "direction": "asc",
        })
        for attempt in range(5):
            status, body, headers = _request(f"{_API}/repos/{repo}/issues?{q}", token)
            if status == 200:
                break
            if status in (403, 429):
                wait = _sleep_for_ratelimit(headers, attempt)
                print(f"  레이트리밋 — {wait:.0f}초 대기", file=sys.stderr)
                time.sleep(wait)
                continue
            raise SystemExit(f"이슈 조회 실패 (HTTP {status}): {body}")
        else:
            raise SystemExit("이슈 조회 재시도 초과")

        if not body:
            return
        for item in body:
            # /issues 는 PR도 함께 준다. pull_request 키가 있으면 PR이다.
            if "pull_request" not in item:
                yield item
        if len(body) < 100:
            return
        page += 1


def close_issue(repo: str, token: str, number: int) -> bool:
    for attempt in range(5):
        status, body, headers = _request(
            f"{_API}/repos/{repo}/issues/{number}", token, method="PATCH",
            payload={"state": "closed", "state_reason": "not_planned"})
        if status == 200:
            return True
        if status in (403, 429):
            time.sleep(_sleep_for_ratelimit(headers, attempt))
            continue
        print(f"  #{number} 종료 실패 (HTTP {status}): {str(body)[:160]}", file=sys.stderr)
        return False
    return False


def main() -> int:
    ap = argparse.ArgumentParser(
        description="오래된 Argus CVE 리포트 이슈를 닫습니다 (기본은 미리보기).")
    ap.add_argument("--days", type=int, default=180,
                    help="이 기간 이상 갱신이 없는 이슈만 대상 (기본 180)")
    ap.add_argument("--label", default="cve", help="대상 라벨 (기본 cve)")
    ap.add_argument("--keep-labels", default="kev,exploited",
                    help="이 라벨이 하나라도 붙어 있으면 남긴다 (쉼표 구분)")
    ap.add_argument("--limit", type=int, default=0, help="최대 종료 건수 (0=제한 없음)")
    ap.add_argument("--apply", action="store_true",
                    help="실제로 닫는다. 없으면 대상만 보여준다")
    args = ap.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN", "")
    if not repo or not token:
        raise SystemExit("GITHUB_REPOSITORY와 GH_TOKEN이 필요합니다 (issues:write).")

    keep = {s.strip().lower() for s in args.keep_labels.split(",") if s.strip()}
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=args.days)

    scanned = kept_recent = kept_label = 0
    targets: List[Dict] = []
    print(f"저장소 {repo} · 라벨 '{args.label}' · {args.days}일 경과 · "
          f"보존 라벨 {sorted(keep) or '없음'}", file=sys.stderr)

    for issue in iter_open_issues(repo, token, args.label):
        scanned += 1
        labels = {l.get("name", "").lower() for l in (issue.get("labels") or [])}
        if labels & keep:
            kept_label += 1
            continue
        try:
            updated = datetime.datetime.fromisoformat(
                str(issue.get("updated_at")).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        if updated >= cutoff:
            # 정렬이 updated 오름차순이라, 여기 닿으면 이후는 전부 최신이다
            kept_recent += 1
            break
        targets.append(issue)
        if args.limit and len(targets) >= args.limit:
            break

    print(f"\n훑은 이슈 {scanned:,} · 종료 대상 {len(targets):,} "
          f"(보존: 라벨 {kept_label:,} · 최근 {kept_recent:,})", file=sys.stderr)
    if not targets:
        print("종료할 이슈가 없습니다.")
        return 0

    for issue in targets[:10]:
        print(f"  #{issue['number']:<6} {str(issue.get('updated_at'))[:10]} "
              f"{str(issue.get('title'))[:70]}")
    if len(targets) > 10:
        print(f"  … 외 {len(targets) - 10:,}건")

    if not args.apply:
        print(f"\n미리보기입니다. 실제로 닫으려면 --apply 를 붙이세요 "
              f"({len(targets):,}건).", file=sys.stderr)
        return 0

    closed = 0
    for i, issue in enumerate(targets, 1):
        if close_issue(repo, token, issue["number"]):
            closed += 1
        if i % 50 == 0:
            print(f"  진행 {i:,}/{len(targets):,} (종료 {closed:,})", file=sys.stderr)
        # 대량 쓰기는 2차 레이트리밋에 걸리기 쉬워 간격을 둔다
        time.sleep(0.6)
    print(f"\n종료 완료: {closed:,}/{len(targets):,}건", file=sys.stderr)
    return 0 if closed == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())
