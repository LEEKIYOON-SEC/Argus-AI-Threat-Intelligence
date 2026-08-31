"""AI가 찾은 취약점 식별 — 'ANT ID'와 그 밖의 AI 발견 프로그램.

━━ 왜 별도 축인가 ━━

이건 **악용 신호가 아니라 출처(provenance) 신호**다. AI가 찾아 책임공개된 취약점은 대개
공개 시점에 이미 패치돼 있다(Anthropic 레저 실측 fix_rate 95.3%). 그래서 "지금 공격받고
있다"와 같은 칸에 넣으면 안 된다. 다만 공개되는 순간 상세가 공개되므로 N-day 위험은
실재하고, 물량이 하루 1~2건 수준이라 알림에 얹어도 노이즈가 되지 않는다.

━━ 두 갈래 ━━

**① Anthropic Disclosure Ledger** (red.anthropic.com)
  구조화된 공개 데이터다. `data/payload.json`의 `cve_records`가 CVE ID ↔ ANT ID를 직접
  이어 준다(실측 69건). `data/ledger.json`은 봉인(sealed) 항목까지 2,736건.
  주의: 페이지 URL(`/ledger/payload.json`)은 사이트 셸 HTML을 200으로 돌려준다 —
  실제 경로는 `/data/` 아래다. 여기서 틀리면 조용히 HTML을 파싱하게 된다.

  라이선스: 페이지에 명시적 라이선스 문구가 없다. 그래서 **사실 데이터만**(CVE ID·ANT ID·
  프로젝트·버그 클래스·날짜) 쓰고 출처를 명시한다. 데이터셋 자체를 우리 것처럼 재배포하지
  않는다. EPSS·KEV와 같은 취급이다.

**② CVE 레코드의 credits 필드**
  소스를 새로 붙일 필요가 없다 — cvelistV5 레코드를 이미 받고 있고 그 안에 있다.
  실측(8,096건/6일): Google Big Sleep 1 · ZeroPath 6 · Claude/Anthropic 4 = 하루 ~2건.

      "Red Hat would like to thank Google Big Sleep for reporting this issue."
      "Nicholas Carlini using Claude, Anthropic"
      "Thai Duong (Calif.io in collaboration with Claude and Anthropic Research)"

  패턴은 **프로그램 고유명만** 쓴다. 'AI'·'LLM'·'OpenAI' 같은 일반어를 넣으면
  'Kostya Kortchinsky | OpenAI'(사람 연구원)처럼 소속을 발견 주체로 오인한다.
  매칭된 크레딧 원문을 그대로 들고 다녀, 오탐이 나면 알림에서 눈에 보이게 한다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

from enrichment_sources import cache_get, cache_put
from logger import logger

_LEDGER_BASE = "https://red.anthropic.com/2026/cvd/data"
_PAYLOAD_URL = f"{_LEDGER_BASE}/payload.json"
_TIMEOUT = 60

#: 프로그램 고유명만. 일반어(AI/LLM/자동화)는 절대 넣지 않는다 — 소속을 발견 주체로
#: 오인하는 오탐이 바로 생긴다.
_PROGRAMS = (
    ("Google Big Sleep", re.compile(r"\bbig\s?sleep\b", re.I)),
    ("Anthropic / Claude", re.compile(r"\b(?:using|with)\s+claude\b|\bclaude\s+and\s+anthropic\b"
                                      r"|\banthropic\s+research\b", re.I)),
    ("ZeroPath", re.compile(r"\bzeropath\b", re.I)),
    ("XBOW", re.compile(r"\bxbow\b", re.I)),
    ("Google CodeMender", re.compile(r"\bcodemender\b", re.I)),
    ("DARPA AIxCC", re.compile(r"\baixcc\b", re.I)),
)


@dataclass(frozen=True)
class Provenance:
    """이 CVE를 누가(무엇이) 찾았는가."""
    program: str
    detail: str          # ANT ID·프로젝트, 또는 크레딧 원문 (근거를 그대로 보여주기 위함)
    url: str = ""

    def as_state(self) -> Dict:
        return {"ai_discovered": True, "ai_program": self.program,
                "ai_detail": self.detail[:300], "ai_url": self.url}


# ──────────────────────────────────────────────────────────────────────────
# ① Anthropic Disclosure Ledger
# ──────────────────────────────────────────────────────────────────────────
def load_anthropic_ledger(ttl_hours: int = 6) -> Optional[Dict[str, Dict]]:
    """{CVE: {ant_id, project, bug_class, severity, title, revealed_at}}. 실패하면 None.

    None과 빈 dict를 구분하는 게 중요하다 — 스냅샷 대조에서 '수신 실패'를 '전부 사라짐'으로
    읽으면 다음 실행에서 전량이 신규로 보여 알림 폭풍이 난다."""
    raw = cache_get("anthropic-cvd.json", ttl_hours=ttl_hours)
    if raw is None:
        try:
            resp = requests.get(_PAYLOAD_URL, timeout=_TIMEOUT,
                                headers={"User-Agent": "argus-provenance"})
            resp.raise_for_status()
            # 사이트가 알 수 없는 경로에 셸 HTML을 200으로 돌려주므로 형식을 확인한다
            if "json" not in (resp.headers.get("Content-Type") or "").lower():
                logger.warning("Anthropic 레저: JSON이 아닌 응답 — 경로 변경 가능성")
                return None
            raw = resp.content
            cache_put("anthropic-cvd.json", raw)
            logger.info(f"📥 Anthropic 공개 레저 수신 ({len(raw) / 1024 / 1024:.1f}MB)")
        except requests.exceptions.RequestException as e:
            logger.warning(f"Anthropic 레저 수신 실패: {e}")
            return None
    try:
        data = json.loads(raw.decode("utf-8", errors="ignore"))
    except ValueError as e:
        logger.warning(f"Anthropic 레저 파싱 실패: {e}")
        return None

    out: Dict[str, Dict] = {}
    for rec in data.get("cve_records") or []:
        cve_id = str(rec.get("identifier") or "").upper()
        if not cve_id.startswith("CVE-"):
            continue
        findings = rec.get("findings") or []
        first = findings[0] if findings else {}
        out[cve_id] = {
            "ant_id": first.get("ant_id", ""),
            "project": first.get("project", ""),
            "bug_class": first.get("bug_class", ""),
            "severity": first.get("severity", ""),
            "title": first.get("title", ""),
            "revealed_at": rec.get("revealed_at", ""),
            "count": len(findings),
        }
    logger.info(f"  ✅ Anthropic CVD: CVE {len(out)}건 (출처: red.anthropic.com)")
    return out


def anthropic_provenance(cve_id: str, ledger: Optional[Dict[str, Dict]]) -> Optional[Provenance]:
    entry = (ledger or {}).get(cve_id.upper())
    if not entry:
        return None
    bits = [b for b in (entry.get("ant_id"), entry.get("project"),
                        entry.get("bug_class")) if b]
    return Provenance(
        program="Anthropic CVD",
        detail=" · ".join(bits) or entry.get("title", ""),
        url="https://red.anthropic.com/2026/cvd/ledger/",
    )


# ──────────────────────────────────────────────────────────────────────────
# ② CVE 레코드의 credits
# ──────────────────────────────────────────────────────────────────────────
def credit_provenance(credits: Optional[List[str]]) -> Optional[Provenance]:
    """크레딧 문자열들에서 AI 발견 프로그램을 찾는다. 없으면 None.

    매칭된 원문을 detail에 그대로 담는다 — 판정 근거를 사람이 바로 확인할 수 있어야
    오탐이 조용히 지나가지 않는다."""
    for text in credits or []:
        s = str(text or "")
        if not s:
            continue
        for program, pattern in _PROGRAMS:
            if pattern.search(s):
                return Provenance(program=program, detail=s.strip())
    return None


def detect(cve_id: str, credits: Optional[List[str]],
           ledger: Optional[Dict[str, Dict]] = None) -> Optional[Provenance]:
    """이 CVE의 AI 발견 출처. 레저(구조화)를 크레딧(자유텍스트)보다 우선한다."""
    return anthropic_provenance(cve_id, ledger) or credit_provenance(credits)
