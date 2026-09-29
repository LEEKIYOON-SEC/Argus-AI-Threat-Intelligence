"""탐지 룰 라이선스 — 룰을 싣는 곳(색인 · 스냅샷 · export)이 모두 이 판정 하나를 쓴다.

화면(docs/js/context.js 의 RULE_LICENSE · ruleTerms)은 출처가 정해진 룰을 같은 표기로 적는다.
둘 중 하나를 바꾸면 다른 쪽도 바꾸고 tests/test_rule_license.py · tests/context.test.js 로 맞춰 본다.

원문 확인 (2026-09-29)
  - ET Open: 배포 LICENSE 기준 SID 2000000–2799999 는 BSD (Copyright (c) 2003-2026, Emerging Threats),
    SID 1–3464 · 100000000–100000908 은 GPLv2, 2800000–2900000 은 ET Pro 라이선스다. 색인은 BSD 범위만 싣는다.
  - Snort Community: community.rules 머리말 — GPLv2 (Copyright 2001-2026 Sourcefire, Inc. 및 각 작성자).
    함께 배포되는 VRT 라이선스 §2.3 은 Community Rules 가 그 계약의 대상이 아니라고 적는다.
  - YARA: YARA Forge 는 룰마다 원 저장소의 LICENSE 링크(license_url)만 준다. 저장소별 라이선스는 아래 표로 정하고,
    표에 없는 저장소나 LICENSE 가 없는 저장소(license_url 'N/A')의 룰은 본문 없이 링크만 싣는다.
"""
import re
from typing import Dict, Optional

SOURCES = {
    "sigma": {"license": "DRL 1.1", "license_url": "https://github.com/SigmaHQ/Detection-Rule-License"},
    "splunk": {"license": "Apache-2.0",
               "license_url": "https://github.com/splunk/security_content/blob/develop/LICENSE"},
    "nuclei": {"license": "MIT",
               "license_url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md"},
    "et-open": {"license": "BSD", "license_url": "https://rules.emergingthreats.net/open/suricata-7.0/LICENSE"},
    "snort-community": {"license": "GPLv2", "license_url": "https://www.gnu.org/licenses/old-licenses/gpl-2.0.html"},
}

# YARA 원 저장소(소문자 owner/repo) → (라이선스, 저작권 문구). 그 저장소의 LICENSE 파일을 직접 확인한 것만 적는다.
# 저작권 문구는 LICENSE 에 적힌 그대로다(2026-09-29 확인) — BSD · MIT 는 사본에 이 문구를 유지하라고 적는다.
# DRL 은 작성자 · 룰 링크 · 라이선스로 충분하고, craiu(GPL-3.0) 저장소에는 저작권 문구가 없어 작성자 표기로 대신한다.
YARA_REPOS = {
    "neo23x0/signature-base": ("DRL 1.1", ""),
    "sekoia-io/community": ("DRL 1.1", ""),
    "ditekshen/detection": ("BSD-2-Clause", "Copyright 2021 by ditekSHen (https://github.com/ditekshen/detection)."),
    "volexity/threat-intel": ("BSD-2-Clause", "Copyright 2022 by Volexity, Inc."),
    "elceef/yara-rulz": ("MIT", "Copyright (c) 2022 Marcin Ulikowski"),
    "craiu/yararules": ("GPL-3.0", ""),
}

NETWORK_ENGINES = ("snort2", "snort3", "suricata5", "suricata7")
LINK_ONLY_ENGINES = ("nuclei",)

_GITHUB = re.compile(r"github\.com/+([^/\s]+)/+([^/\s#?]+)", re.I)


def source_of(rule: Dict) -> Optional[str]:
    """룰이 온 곳 — 네트워크 룰은 엔진이 같아도 ET Open(BSD)과 Snort Community(GPLv2)로 나뉜다."""
    engine = rule.get("engine") or ""
    if engine in NETWORK_ENGINES:
        return "snort-community" if "community" in (rule.get("source") or "").lower() else "et-open"
    return engine or None


def repo_of(url: str) -> str:
    m = _GITHUB.search(url or "")
    return f"{m.group(1)}/{m.group(2)}".lower() if m else ""


def et_open_sid_ok(sid: Optional[int]) -> bool:
    """ET Open 배포본에서 BSD 로 배포되는 SID 범위인가."""
    return sid is not None and 2000000 <= sid <= 2799999


def terms(rule: Dict) -> Dict:
    """룰 하나에 적을 라이선스 — {license, license_url, holder, link_only}. link_only 면 본문을 싣지 않는다.
    holder 는 YARA 원 저장소의 저작권 문구다(ET Open · Snort Community 의 저작권 줄은 화면이 출처로 안다)."""
    engine = rule.get("engine") or ""
    if engine == "yara":
        lic_url = str(rule.get("license_url") or "")
        if not lic_url.lower().startswith(("http://", "https://")):
            return {"license": "", "license_url": "", "holder": "", "link_only": True}
        name, holder = YARA_REPOS.get(repo_of(lic_url), ("", ""))
        return {"license": name, "license_url": lic_url, "holder": holder, "link_only": not name}
    base = SOURCES.get(source_of(rule) or "")
    if base is None:
        return {"license": str(rule.get("license") or ""), "license_url": str(rule.get("license_url") or ""),
                "holder": "", "link_only": engine in LINK_ONLY_ENGINES}
    return {"license": base["license"], "license_url": base["license_url"], "holder": "",
            "link_only": engine in LINK_ONLY_ENGINES}


def apply(rule: Dict) -> Dict:
    """라이선스 표기를 바로잡은 사본. 본문을 실을 수 없는 룰은 code 를 뺀다. 여러 번 적용해도 결과가 같다.

    license_url · holder(저작권 문구)는 룰마다 다른 YARA 에만 남긴다 — 출처가 정해진 룰은 화면이 출처로 안다.
    """
    out = {k: v for k, v in rule.items() if k != "note"}
    t = terms(rule)
    out["license"] = t["license"]
    if out.get("engine") == "yara":
        out["license_url"] = t["license_url"]
        if t["holder"]:
            out["holder"] = t["holder"]
        else:
            out.pop("holder", None)
    else:
        out.pop("license_url", None)
        out.pop("holder", None)
    if t["link_only"]:
        out.pop("code", None)
        out["link_only"] = True
    else:
        out.pop("link_only", None)
    return out
