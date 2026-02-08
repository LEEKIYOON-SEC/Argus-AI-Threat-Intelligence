from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .groq_llm import GroqLLM, safe_json_loads
from .rule_validation import validate_by_engine
from .rule_router import decide_rule_scope
from .util.textutil import sha256_hex

log = logging.getLogger("argus.ai_rules")


@dataclass
class GeneratedRule:
    engine: str          # sigma/yara/suricata/snort2/snort3
    rule_text: str
    confidence: str
    notes: str
    validated: bool
    validation_details: str
    fingerprint: str


def _fp(text: str) -> str:
    return sha256_hex((text or "").encode("utf-8"))


def _system_prompt() -> str:
    return (
        "You are a senior detection engineer.\n"
        "Goal: Generate high-precision, low-false-positive detection rules for a specific CVE.\n"
        "Constraints:\n"
        "- You CANNOT browse the web.\n"
        "- Use ONLY the Evidence Bundle text I provide.\n"
        "- Prefer indicators that are specific to exploitation and stable (protocol fields, endpoints, headers, error strings, process/command patterns, log fields).\n"
        "- Avoid generic strings that cause false positives.\n"
        "- If evidence is insufficient, set needs_more_evidence=true and request exact evidence types.\n"
    )


def _schema_hint() -> str:
    return """{
  "needs_more_evidence": false,
  "requested_evidence": [],
  "rules": [
    {
      "engine": "sigma|yara|suricata|snort2|snort3",
      "rule_text": "string",
      "confidence": "high|medium|low",
      "notes": "string"
    }
  ]
}"""


def _build_user_prompt(cve: dict, evidence_bundle_text: str, engines: List[str]) -> str:
    """
    입력은 영어로(모델 성능 극대화), 출력은 룰 원문 그대로.
    - 최종 Slack/Report는 한글 중심이지만, 룰 자체는 원문 유지 정책.
    """
    cve_id = cve["cve_id"]
    cvss = cve.get("cvss_score")
    vector = cve.get("cvss_vector")
    av = cve.get("attack_vector")
    desc = cve.get("description_en") or ""
    cwe = ", ".join(cve.get("cwe_ids") or [])

    return (
        f"CVE: {cve_id}\n"
        f"CVSS: {cvss}\n"
        f"Vector: {vector}\n"
        f"Attack Vector: {av}\n"
        f"CWE: {cwe}\n"
        f"Description (EN):\n{desc}\n\n"
        f"Target rule engines to generate (in priority order): {', '.join(engines)}\n\n"
        "Evidence Bundle (normalized text, authoritative for this task):\n"
        "----- BEGIN EVIDENCE BUNDLE -----\n"
        f"{evidence_bundle_text}\n"
        "----- END EVIDENCE BUNDLE -----\n\n"
        "Rules requirements:\n"
        "- Sigma rule MUST be generated (even if other engines are not requested).\n"
        "- For network rules (Snort/Suricata), target specific exploit traffic patterns (URI paths, parameters, headers, body markers) only if evidenced.\n"
        "- For YARA, target artifact patterns ONLY if evidenced (payload strings, file structure hints, class names).\n"
        "- Use stable fields; keep false positives low.\n"
        "- For Sigma, choose logsource appropriately and provide meaningful detection + condition.\n"
        "- Output JSON only.\n"
    )


def generate_ai_rules(
    *,
    cfg,
    cve: dict,
    evidence_bundle_text: str,
    prefer_snort3: bool = False,
) -> List[GeneratedRule]:
    """
    공개/공식 룰이 없을 때 AI로 생성.
    - Sigma는 무조건 생성
    - Snort/Suricata/YARA는 router 결정에 따라
    - 생성된 룰은 엔진별 검증 통과한 것만 'validated=True'

    prefer_snort3:
      - 기업 환경이 Snort3 중심이면 True로 설정 가능(추후 정책화)
    """
    decision = decide_rule_scope(cve)

    # Sigma는 항상 포함
    engines: List[str] = ["sigma"]

    if decision.include_network_rules:
        # snort vs suricata: 둘 다 필요할 수 있으나,
        # AI 생성은 비용(토큰)과 품질 리스크가 있으므로
        # 기본은 Suricata 1개 + (선택) Snort2/3 중 하나
        engines.append("suricata")
        engines.append("snort3" if prefer_snort3 else "snort2")

    if decision.include_yara:
        engines.append("yara")

    llm = GroqLLM(api_key=cfg.GROQ_API_KEY)

    user_prompt = _build_user_prompt(cve, evidence_bundle_text, engines)
    res = llm.chat_json(
        system=_system_prompt(),
        user=user_prompt,
        json_schema_hint=_schema_hint(),
        temperature=0.15,
        max_tokens=2500,
    )

    if not res.ok:
        log.warning("LLM call failed: %s", res.raw)
        return []

    parsed = safe_json_loads(res.content)
    if not parsed or not isinstance(parsed, dict):
        log.warning("LLM JSON parse failed")
        return []

    if parsed.get("needs_more_evidence") is True:
        # 운영상: 증거 부족이면 빈 결과 반환(다음 단계에서 report에 요청증거를 기록하도록 연결)
        log.info("LLM indicates insufficient evidence: %s", parsed.get("requested_evidence"))
        return []

    rules = parsed.get("rules") or []
    out: List[GeneratedRule] = []

    for r in rules:
        if not isinstance(r, dict):
            continue
        engine = (r.get("engine") or "").strip().lower()
        text = (r.get("rule_text") or "").strip()
        if not engine or not text:
            continue

        # Sigma는 반드시 있어야 함. 모델이 빼먹으면 다음 단계에서 강제 생성 fallback 추가.
        vr = validate_by_engine(engine, text)
        out.append(
            GeneratedRule(
                engine=engine,
                rule_text=text + "\n",
                confidence=(r.get("confidence") or "medium"),
                notes=(r.get("notes") or ""),
                validated=bool(vr.ok),
                validation_details=vr.details,
                fingerprint=_fp(text),
            )
        )

    # Sigma 강제: 없으면 최소 스켈레톤 생성(검증 통과 목표)
    if not any(x.engine == "sigma" for x in out):
        skeleton = _sigma_skeleton(cve)
        vr = validate_by_engine("sigma", skeleton)
        out.append(
            GeneratedRule(
                engine="sigma",
                rule_text=skeleton,
                confidence="low",
                notes="LLM did not produce sigma; inserted conservative skeleton.",
                validated=bool(vr.ok),
                validation_details=vr.details,
                fingerprint=_fp(skeleton),
            )
        )

    return out


def _sigma_skeleton(cve: dict) -> str:
    """
    증거가 부족할 때도 Sigma '형식'을 만족하는 최소 룰.
    - 오탐/미탐이 있을 수 있으므로 confidence low로 표시
    - 다음 단계에서 Evidence Bundle이 확보되면 대체/개선됨
    """
    cve_id = cve["cve_id"]
    title = f"Potential exploitation activity related to {cve_id}"
    return (
        f"title: {title}\n"
        f"id: 00000000-0000-4000-8000-000000000000\n"
        f"status: experimental\n"
        f"description: |\n"
        f"  Skeleton sigma rule for {cve_id}. Replace with evidence-based rule when available.\n"
        f"references:\n"
        f"  - {cve_id}\n"
        f"author: Argus-AI-Threat Intelligence\n"
        f"date: 2026/02/08\n"
        f"tags:\n"
        f"  - attack.initial_access\n"
        f"logsource:\n"
        f"  product: windows\n"
        f"  category: process_creation\n"
        f"detection:\n"
        f"  selection:\n"
        f"    CommandLine|contains:\n"
        f"      - '{cve_id}'\n"
        f"  condition: selection\n"
        f"falsepositives:\n"
        f"  - Unknown\n"
        f"level: medium\n"
    )
