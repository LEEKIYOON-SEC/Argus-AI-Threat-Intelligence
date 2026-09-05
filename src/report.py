from typing import Dict, Optional, Tuple

from analyzer import Analyzer
from logger import logger
from rule_manager import RuleManager
from rule_manager import index_ok as rule_manager_index_ok

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

        rules, complete = RuleManager().search_public_only(cve_data['id'])
        if not rule_manager_index_ok() or not complete:
            return analysis, None
        has_official = bool(
            rules.get('network')
            or any(rules.get(k) for k in ('sigma', 'nuclei', 'splunk', 'yara'))
        )
        return analysis, {"has_official": has_official, "rules": rules}

    except Exception as e:
        logger.error(f"{cve_data.get('id')} AI 분석 실패: {e}")
        return None, None
