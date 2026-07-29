"""GitHub Issue 기반 대응 상태 수집.

Argus는 고위험 CVE마다 GitHub Issue(상세 리포트)를 만든다. 그 이슈의 상태가 곧
대응 상태다 — 담당자가 조치를 마치고 닫으면 '완료', `in-progress` 라벨을 붙이면 '조치 중'.
별도 티켓 시스템·DB 컬럼 없이 이미 쓰고 있는 도구만으로 취약점 관리 사이클을 닫는다.

비용 설계: 전체 이슈를 매번 훑으면 수천 건 × 매시간이라 낭비다. 대신 '기본값에서
벗어난 것'만 조회한다 — 닫힌 이슈 + in-progress 라벨 이슈. 둘 다 소수라 보통 1~2콜로 끝난다.
(조회되지 않은 나머지는 자동으로 '미대응'이다.)
"""

import os
import re
import requests
from typing import Dict, Optional
from logger import logger

_API = "https://api.github.com"
_CVE_RE = re.compile(r'(CVE-\d{4}-\d{4,7})')
_PER_PAGE = 100
_MAX_PAGES = 10          # 안전 상한 (최대 1,000건까지만 — 그 이상은 다음 실행에서)


def _headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}


def _collect(repo: str, token: str, params: Dict, status: str,
             out: Dict[str, str], overwrite: bool) -> int:
    """조건에 맞는 이슈를 페이지네이션으로 훑어 cve_id → status 로 채운다."""
    found = 0
    for page in range(1, _MAX_PAGES + 1):
        q = dict(params, per_page=_PER_PAGE, page=page)
        resp = requests.get(f"{_API}/repos/{repo}/issues", headers=_headers(token),
                            params=q, timeout=15)
        resp.raise_for_status()
        items = resp.json() or []
        if not items:
            break
        for it in items:
            if "pull_request" in it:      # 이슈 API는 PR도 함께 반환한다
                continue
            m = _CVE_RE.search(it.get("title") or "")
            if not m:
                continue
            cve_id = m.group(1)
            if overwrite or cve_id not in out:
                out[cve_id] = status
                found += 1
        if len(items) < _PER_PAGE:
            break
    return found


def fetch_issue_status(repo: Optional[str] = None,
                       token: Optional[str] = None) -> Dict[str, str]:
    """cve_id → 'done' | 'in_progress' 매핑. 실패 시 빈 dict (대시보드는 전부 미대응 표시).

    'done'(닫힘)이 'in_progress'(라벨)보다 우선한다 — 라벨을 단 채 닫은 경우 완료로 본다.
    """
    repo = repo or os.environ.get("GITHUB_REPOSITORY", "")
    token = token or os.environ.get("GH_TOKEN", "")
    if not repo or not token:
        logger.info("이슈 상태 동기화 생략 (GITHUB_REPOSITORY/GH_TOKEN 미설정)")
        return {}

    out: Dict[str, str] = {}
    try:
        # 1) 조치 중 — open + in-progress 라벨 (소수)
        n_prog = _collect(repo, token, {"state": "open", "labels": "in-progress"},
                          "in_progress", out, overwrite=False)
        # 2) 완료 — 닫힌 CVE 이슈 (소수). 나중에 덮어써 'done' 우선을 보장
        n_done = _collect(repo, token, {"state": "closed", "labels": "cve"},
                          "done", out, overwrite=True)
        logger.info(f"이슈 대응 상태: 조치 중 {n_prog}건 · 완료 {n_done}건")
        return out
    except Exception as e:
        logger.warning(f"이슈 상태 조회 실패(무시하고 진행): {e}")
        return {}
