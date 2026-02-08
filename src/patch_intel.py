from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from bs4 import BeautifulSoup

from .http import http_get

log = logging.getLogger("argus.patch_intel")


@dataclass
class PatchFinding:
    kind: str           # "vendor_advisory" | "release_note" | "patch" | "workaround" | "other"
    title: str
    url: str
    extracted_text: str  # URL을 LLM에 주지 않기 위해, 페이지에서 추출한 정규화 텍스트


def _html_to_text(html: bytes, max_chars: int = 6000) -> str:
    """
    HTML을 텍스트로 정규화(LLM Evidence Bundle에 넣기 위함).
    - JS 렌더링이 필요한 페이지는 한계가 있음(그 경우 extracted_text가 빈약해질 수 있음)
    """
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        # 공백 정리
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]{2,}", " ", text)
        text = text.strip()
        if len(text) > max_chars:
            text = text[:max_chars] + "\n...(truncated)"
        return text
    except Exception:
        return ""


def _classify_url(url: str) -> str:
    u = (url or "").lower()
    if any(k in u for k in ["advisory", "security", "bulletin", "kb", "cve"]):
        return "vendor_advisory"
    if any(k in u for k in ["release", "changelog", "notes", "version"]):
        return "release_note"
    if any(k in u for k in ["patch", "download", "fix"]):
        return "patch"
    if any(k in u for k in ["workaround", "mitigation"]):
        return "workaround"
    return "other"


def fetch_patch_findings_from_references(
    references: List[str],
    *,
    max_pages: int = 4,
    per_page_text_limit: int = 6000,
) -> List[PatchFinding]:
    """
    '가능하면 무조건' 공식 패치/권고를 확보하기 위한 1차 수집기.
    - 입력: CVE references URL 리스트
    - 출력: PatchFinding 리스트(정규화된 텍스트 포함)

    운영 안정성/비용 0 전제를 위해:
    - 너무 많은 페이지를 무작정 크롤링하지 않음(max_pages 제한)
    - 다운로드/텍스트 추출 실패는 무시하고 계속 진행
    """
    out: List[PatchFinding] = []
    if not references:
        return out

    # 우선순위: advisory/release/patch 관련 키워드 URL을 앞에 두고, 그 외는 뒤로
    ranked = sorted(references, key=lambda u: 0 if _classify_url(u) != "other" else 1)

    for url in ranked[:max_pages]:
        try:
            raw = http_get(url, timeout=40, headers={"Accept": "text/html,application/xhtml+xml"})
            text = _html_to_text(raw, max_chars=per_page_text_limit)
            if not text:
                continue
            kind = _classify_url(url)
            title = text.splitlines()[0][:200] if text.splitlines() else url
            out.append(PatchFinding(kind=kind, title=title, url=url, extracted_text=text))
        except Exception as e:
            log.info("patch page fetch failed: %s (%s)", url, e)
            continue

    return out


def build_patch_section_md(findings: List[PatchFinding]) -> str:
    """
    Report에 붙일 '패치/벤더 권고' 섹션 Markdown.
    - Slack에는 길이 폭발 가능성이 높아 기본적으로 Report에만 포함하는 방향.
    """
    lines: List[str] = []
    lines.append("## 7) Vendor Patch / Advisory (Best-effort)")
    if not findings:
        lines.append("- No patch/advisory text could be extracted from references in this run.")
        lines.append("- NOTE: Some vendor pages require JS rendering or authentication.")
        return "\n".join(lines).strip() + "\n"

    for i, f in enumerate(findings, 1):
        lines.append(f"### 7.{i} {f.kind} :: {f.title}")
        lines.append(f"- URL: {f.url}")
        lines.append("")
        lines.append("Extracted (normalized) text:")
        lines.append("```")
        # 너무 길면 이미 _html_to_text에서 truncate됨
        lines.append(f.extracted_text)
        lines.append("```")
        lines.append("")
    return "\n".join(lines).strip() + "\n"
