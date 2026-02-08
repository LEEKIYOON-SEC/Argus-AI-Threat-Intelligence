from __future__ import annotations

import logging
from typing import Dict, Any, List, Optional

from ..http import http_get
from ..util.ziputil import iter_zip_text_files
from ..util.textutil import contains_cve_id

log = logging.getLogger("argus.rules.snort_community")


def fetch_snort_community_hits(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    Snort Community 룰 수집(옵션):
    - cfg.SNORT_COMMUNITY_ZIP_URL 이 설정된 경우에만 ZIP을 다운로드하여 스캔
    - 비용 0 유지 + 안정 URL이 있을 때만 사용
    - CVE-ID 포함 룰은 전부 수집

    NOTE:
      Snort Community 룰은 배포 정책/인증/URL이 바뀔 수 있어
      확정적으로 '항상 다운로드'는 위험합니다.
      그래서 "옵션 URL 제공 시 1차 다운로드"로만 구현하고,
      추후 단계에서 GitHub Search API 보강(2차)을 추가합니다.
    """
    url: Optional[str] = getattr(cfg, "SNORT_COMMUNITY_ZIP_URL", None)
    if not url:
        return []

    cve_id = cve_id.upper().strip()
    hits: List[Dict[str, Any]] = []

    try:
        blob = http_get(url, timeout=180)
        scanned = 0
        for path, text in iter_zip_text_files(blob):
            # community rules가 .rules 또는 .txt로 들어있는 경우가 많아 둘 다 허용
            if not path.endswith((".rules", ".txt")):
                continue
            scanned += 1
            if contains_cve_id(text, cve_id):
                hits.append(
                    {
                        "source": "SNORT_COMMUNITY",
                        "engine": "snort2",  # community rules는 전통적으로 snort2 포맷이 많음
                        "rule_path": path,
                        "rule_text": text.strip() + "\n",
                        "reference": f"{url} :: {path}",
                        "cve_ids": [cve_id],
                    }
                )
        log.info("Snort Community scanned=%d hits=%d", scanned, len(hits))
    except Exception as e:
        log.warning("Snort Community fetch/scan failed: %s", e)

    return hits
