import json
import os
import threading
from typing import Dict, Optional, Tuple

from analyzer import Analyzer
from logger import logger
from rule_manager import RuleManager
from rule_manager import index_ok as rule_manager_index_ok

_PKG_INDEX: Optional[Dict] = None
_PKG_INDEX_LOCK = threading.Lock()


def _package_index() -> Dict:
    global _PKG_INDEX
    if _PKG_INDEX is not None:
        return _PKG_INDEX
    with _PKG_INDEX_LOCK:
        if _PKG_INDEX is None:
            _PKG_INDEX = _load_package_index()
    return _PKG_INDEX


def _load_package_index() -> Dict:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        url = f"https://{owner.lower()}.github.io/{name}/data/cve-packages.json"
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "argus-report"})
            with urllib.request.urlopen(req, timeout=180) as r:
                idx = (json.loads(r.read().decode("utf-8")) or {}).get("packages") or {}
            logger.info(f"패키지 사전 로드(배포본): {len(idx):,}건")
            return idx
        except Exception as e:
            logger.warning(f"패키지 사전 배포본 로드 실패({e}) → 체크아웃 사본 확인")

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "docs", "data", "cve-packages.json")
    try:
        with open(path, encoding="utf-8") as f:
            idx = (json.load(f) or {}).get("packages") or {}
        logger.info(f"패키지 사전 로드(파일): {len(idx):,}건")
        return idx
    except (OSError, ValueError):
        return {}


_MAX_FIELD = 1200
_MAX_MITIGATION = 6


def _clip(value, cap: int = _MAX_FIELD) -> str:
    text = str(value or "").strip()
    return text[:cap] if len(text) > cap else text


def compact(analysis: Optional[Dict]) -> Optional[Dict]:
    if not isinstance(analysis, dict):
        return None
    out = {}
    for key in ("root_cause", "scenario", "impact"):
        value = _clip(analysis.get(key))
        if value and value not in ("-", "정보 없음"):
            out[key] = value
    steps = [_clip(m, 300) for m in (analysis.get("mitigation") or [])]
    steps = [m for m in steps if m][:_MAX_MITIGATION]
    if steps:
        out["mitigation"] = steps
    return out or None


def make_analysis(cve_data: Dict, reason: str) -> Tuple[Optional[Dict], Optional[Dict]]:
    try:
        logger.info(f"AI 분석 시작: {cve_data['id']}")
        analysis = compact(Analyzer().analyze_cve(cve_data))
        if not analysis:
            logger.warning(f"{cve_data['id']} 분석 결과가 비었다 — 저장하지 않는다")
            return None, None

        rules = RuleManager().search_public_only(cve_data['id'])
        if not rule_manager_index_ok():
            return analysis, None
        has_official = bool(
            rules.get('network')
            or any(rules.get(k) for k in ('sigma', 'nuclei', 'splunk', 'yara'))
        )
        return analysis, {"has_official": has_official, "rules": rules}

    except Exception as e:
        logger.error(f"{cve_data.get('id')} AI 분석 실패: {e}")
        return None, None
