#!/usr/bin/env python3
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
        time.sleep(0.6)
    print(f"\n종료 완료: {closed:,}/{len(targets):,}건", file=sys.stderr)
    return 0 if closed == len(targets) else 1


if __name__ == "__main__":
    sys.exit(main())
