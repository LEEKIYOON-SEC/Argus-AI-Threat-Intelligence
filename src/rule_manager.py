"""공개 탐지 룰 조회 — 인덱스에서 찾고, 원문은 필요할 때만 받는다.

예전에는 **CVE 한 건마다** SigmaHQ 전체 파일과 ET Open 룰셋 3종(각 수십 MB)을 정규식으로
선형 스캔했다. 히트율은 실측 1.1% — 98.9%는 수십 MB를 훑어 '없음'을 확인하는 데 시간을
썼고, 그 검색이 매시간 실행의 맨 앞에 있었다.

이제 주 1회 build_rule_index.py가 만든 CVE→룰 위치 인덱스를 조회한다. 조회는 O(1)이고,
룰 원문은 리포트를 발행하는 순간에만 받는다.

원문을 재게시할 때는 출처·author·라이선스 고지를 함께 싣는다(불변 원칙 8-①).
그 고지는 인덱스가 항목마다 들고 있으므로 여기서 추측하지 않는다.
"""
import json
import os
import threading
from typing import Dict, List, Optional

import requests

from logger import logger

_INDEX_LOCK = threading.Lock()
_INDEX: Optional[Dict[str, List[Dict]]] = None

_LOCAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "docs", "data", "detection-rules.json")

#: 리포트에 싣는 룰 원문의 상한. 넘으면 잘라 싣고 원문 링크를 준다.
_MAX_RULE_CHARS = 6000


def _index() -> Dict[str, List[Dict]]:
    """인덱스를 1회 적재해 캐시. 못 구하면 빈 dict(기능만 조용히 생략).

    배포본을 먼저 본다 — 데이터 파일을 커밋하지 않으므로 체크아웃에는 없거나 옛날 것이다.
    락이 필요한 이유는 report 생성이 병렬이라 여럿이 동시에 들어오기 때문이다."""
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    with _INDEX_LOCK:
        if _INDEX is None:
            _INDEX = _load()
    return _INDEX


def _load() -> Dict[str, List[Dict]]:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" in repo:
        owner, name = repo.split("/", 1)
        url = f"https://{owner.lower()}.github.io/{name}/data/detection-rules.json"
        try:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "argus-rules"})
            with urllib.request.urlopen(req, timeout=120) as r:
                idx = (json.loads(r.read().decode("utf-8")) or {}).get("rules") or {}
            logger.info(f"탐지 룰 인덱스 로드(배포본): {len(idx):,}건")
            return idx
        except Exception as e:
            logger.warning(f"탐지 룰 인덱스 배포본 로드 실패({e}) → 체크아웃 사본 확인")
    try:
        with open(_LOCAL, encoding="utf-8") as f:
            idx = (json.load(f) or {}).get("rules") or {}
        logger.info(f"탐지 룰 인덱스 로드(파일): {len(idx):,}건")
        return idx
    except (OSError, ValueError):
        logger.info("탐지 룰 인덱스 없음 — 룰 섹션은 생략된다")
        return {}


def _fetch_text(entry: Dict) -> Optional[str]:
    """룰 원문. 인덱스에 code가 있으면(네트워크 룰) 그대로, 없으면 raw로 받는다."""
    if entry.get("code"):
        return entry["code"]
    url = entry.get("url") or ""
    raw = (url.replace("https://github.com/", "https://raw.githubusercontent.com/")
              .replace("/blob/", "/"))
    if not raw.startswith("http"):
        return None
    try:
        resp = requests.get(raw, timeout=30, headers={"User-Agent": "argus-rules"})
        resp.raise_for_status()
        text = resp.text
        if len(text) > _MAX_RULE_CHARS:
            text = text[:_MAX_RULE_CHARS] + "\n# … (생략 — 전체는 출처 링크 참조)"
        return text
    except requests.exceptions.RequestException as e:
        logger.debug(f"룰 원문 수신 실패({raw}): {e}")
        return None


class RuleManager:
    """인덱스 조회기. 예전의 '룰셋 다운로드 + 전수 스캔'은 build_rule_index.py로 옮겼다."""

    def __init__(self):
        logger.debug("RuleManager 초기화 (인덱스 조회 전용)")

    @staticmethod
    def lookup(cve_id: str) -> List[Dict]:
        """CVE에 매핑된 룰 항목들 (원문 없이 위치·출처·라이선스만). 없으면 빈 목록."""
        return _index().get(cve_id.upper(), [])

    def search_public_only(self, cve_id: str) -> Dict:
        """리포트용 룰 묶음. 원문은 여기서만 받는다.

        반환 형식은 기존 소비자(report._build_issue_body, notifier)를 위해 유지한다:
            {"sigma": {...} | None, "network": [...], "yara": {...} | None,
             "nuclei": {...} | None, "splunk": {...} | None}
        """
        entries = self.lookup(cve_id)
        rules: Dict = {"sigma": None, "network": [], "yara": None,
                       "nuclei": None, "splunk": None}
        if not entries:
            return rules

        for entry in entries:
            engine = entry.get("engine", "")
            packed = {
                "source": entry.get("source", ""),
                "engine": engine,
                "license": entry.get("license", ""),
                "note": entry.get("note", ""),
                "url": entry.get("url", ""),
                "author": entry.get("author", ""),
                "license_url": entry.get("license_url", ""),
                "verified": True,      # 공개 룰셋은 출처 자체가 검증 주체다
            }
            if engine in ("snort2", "snort3", "suricata5", "suricata7"):
                if len(rules["network"]) >= 3:
                    continue
                code = _fetch_text(entry)
                if code:
                    rules["network"].append({**packed, "code": code})
            elif engine in ("sigma", "yara", "nuclei", "splunk"):
                if rules.get(engine):
                    continue           # 엔진당 하나면 충분하다
                code = _fetch_text(entry)
                if code:
                    rules[engine] = {**packed, "code": code}

        found = [k for k in ("sigma", "yara", "nuclei", "splunk") if rules.get(k)]
        if rules["network"]:
            found.append(f"network({len(rules['network'])})")
        if found:
            logger.info(f"  ✅ 공개 룰: {cve_id} — {', '.join(found)}")
        return rules
