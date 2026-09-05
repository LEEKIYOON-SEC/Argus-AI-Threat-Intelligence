import json
import os
import threading
from typing import Dict, List, Optional, Tuple

import requests

from logger import logger

_INDEX_LOCK = threading.Lock()
_INDEX: Optional[Dict[str, List[Dict]]] = None
_INDEX_OK = False

_LOCAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "docs", "data", "detection-rules.json")

_MAX_RULE_CHARS = 6000


def _index() -> Dict[str, List[Dict]]:
    global _INDEX, _INDEX_OK
    if _INDEX is not None:
        return _INDEX
    with _INDEX_LOCK:
        if _INDEX is None:
            _INDEX, _INDEX_OK = _load()
    return _INDEX


def index_ok() -> bool:
    _index()
    return _INDEX_OK


def _load() -> Tuple[Dict[str, List[Dict]], bool]:
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
            return idx, True
        except Exception as e:
            logger.warning(f"탐지 룰 인덱스 배포본 로드 실패({e}) → 체크아웃 사본 확인")
    try:
        with open(_LOCAL, encoding="utf-8") as f:
            idx = (json.load(f) or {}).get("rules") or {}
        logger.info(f"탐지 룰 인덱스 로드(파일): {len(idx):,}건")
        return idx, True
    except (OSError, ValueError):
        logger.warning("탐지 룰 인덱스를 받지 못했다 — '룰 없음'으로 기록하지 않는다")
        return {}, False


def _fetch_text(entry: Dict) -> Optional[str]:
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
    def __init__(self):
        logger.debug("RuleManager 초기화 (인덱스 조회 전용)")


    @staticmethod
    def lookup(cve_id: str) -> List[Dict]:
        return _index().get(cve_id.upper(), [])


    def search_public_only(self, cve_id: str) -> Tuple[Dict, bool]:
        entries = self.lookup(cve_id)
        rules: Dict = {"sigma": None, "network": [], "yara": None,
                       "nuclei": None, "splunk": None}
        if not entries:
            return rules, True

        missed = 0
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
                "verified": True,
            }
            if engine in ("snort2", "snort3", "suricata5", "suricata7"):
                if len(rules["network"]) >= 3:
                    continue
                code = _fetch_text(entry)
                if code:
                    rules["network"].append({**packed, "code": code})
                else:
                    missed += 1
            elif engine in ("sigma", "yara", "nuclei", "splunk"):
                if rules.get(engine):
                    continue
                code = _fetch_text(entry)
                if code:
                    rules[engine] = {**packed, "code": code}
                else:
                    missed += 1

        if missed:
            logger.warning(f"  {cve_id}: 색인에 있는 룰 {missed}건의 원문을 받지 못했다 "
                           f"— '룰 없음'으로 기록하지 않는다")
            return rules, False

        found = [k for k in ("sigma", "yara", "nuclei", "splunk") if rules.get(k)]
        if rules["network"]:
            found.append(f"network({len(rules['network'])})")
        if found:
            logger.info(f"  ✅ 공개 룰: {cve_id} — {', '.join(found)}")
        return rules, True
