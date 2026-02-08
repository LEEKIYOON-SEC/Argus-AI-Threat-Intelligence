from __future__ import annotations

import logging
from typing import Dict, Any, List

from ..http import http_get
from ..util.ziputil import iter_zip_text_files
from ..util.textutil import contains_cve_id

log = logging.getLogger("argus.rules.yara_rules")

YARA_RULES_ZIP = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"


def fetch_yara_rules_hits(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    Yara-Rules repo ZIP을 다운로드하여 CVE-ID가 포함된 룰(.yar/.yara)을 전부 수집.
    - Host/파일 기반 탐지가 필요할 때 우선 사용
    - 정책상 불필요하면(네트워크 전용) 나중 단계에서 라우팅으로 제외 가능
    """
    cve_id = cve_id.upper().strip()
    hits: List[Dict[str, Any]] = []

    try:
        blob = http_get(YARA_RULES_ZIP, timeout=180)
        scanned = 0
        for path, text in iter_zip_text_files(blob):
            if not path.endswith((".yar", ".yara")):
                continue
            scanned += 1
            if contains_cve_id(text, cve_id):
                hits.append(
                    {
                        "source": "YARA_RULES",
                        "engine": "yara",
                        "rule_path": path,
                        "rule_text": text.strip() + "\n",
                        "reference": f"{YARA_RULES_ZIP} :: {path}",
                        "cve_ids": [cve_id],
                    }
                )
        log.info("Yara-Rules scanned=%d hits=%d", scanned, len(hits))
    except Exception as e:
        log.warning("Yara-Rules fetch/scan failed: %s", e)

    return hits
