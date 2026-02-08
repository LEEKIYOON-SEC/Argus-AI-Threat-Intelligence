from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

log = logging.getLogger("argus.groq_llm")

# Groq는 OpenAI 호환 경로를 제공하는 것으로 널리 사용됨.
# (환경/정책 변화 가능성은 있으나, 여기서는 운영상 가장 안정적인 기본값을 사용)
DEFAULT_GROQ_BASE_URL = "https://api.groq.com/openai/v1"


@dataclass
class LLMResult:
    ok: bool
    content: str
    raw: dict


class GroqLLM:
    def __init__(
        self,
        api_key: str,
        model: str = "meta-llama/llama-4-maverick-17b-128e-instruct",
        base_url: str = DEFAULT_GROQ_BASE_URL,
        timeout: int = 90,
    ):
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def chat_json(
        self,
        *,
        system: str,
        user: str,
        json_schema_hint: str,
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> LLMResult:
        """
        Groq chat completions 호출.
        - '웹검색 불가' 전제: system에서 강제
        - 결과는 "JSON only"로 강제하여 후처리/검증 안정화
        """
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        # JSON-only 강제(모델이 어길 수 있으므로 후단에서 재파싱/리트라이 로직은 다음 단계에서 확장 가능)
        system_msg = system.strip() + "\n\n" + (
            "IMPORTANT:\n"
            "- You cannot browse the web.\n"
            "- You MUST rely only on the Evidence Bundle text provided.\n"
            "- Output MUST be valid JSON ONLY. No markdown fences, no extra text.\n"
            "- If evidence is insufficient, output JSON with `needs_more_evidence: true` and explain what evidence is needed.\n"
        )

        user_msg = (
            user.strip()
            + "\n\n=== REQUIRED JSON OUTPUT SCHEMA (hint) ===\n"
            + json_schema_hint.strip()
        )

        payload = {
            "model": self.model,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": user_msg},
            ],
        }

        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)
            if resp.status_code >= 400:
                return LLMResult(False, "", {"http": resp.status_code, "text": resp.text[:500]})

            j = resp.json()
            # OpenAI 호환: choices[0].message.content
            content = (
                (((j.get("choices") or [])[0] or {}).get("message") or {}).get("content")
                if isinstance(j, dict)
                else ""
            )
            if not isinstance(content, str):
                content = str(content)

            return LLMResult(True, content, j)

        except Exception as e:
            return LLMResult(False, "", {"exception": str(e)})


def safe_json_loads(text: str) -> Optional[dict]:
    """
    모델이 JSON-only를 어긴 경우를 대비한 보수적 파서.
    - 앞뒤 공백 제거
    - 가장 바깥 {} 구간만 추출 시도
    """
    t = (text or "").strip()
    if not t:
        return None
    try:
        return json.loads(t)
    except Exception:
        # 가장 바깥 중괄호를 찾는 단순 복구
        i = t.find("{")
        j = t.rfind("}")
        if i >= 0 and j > i:
            try:
                return json.loads(t[i : j + 1])
            except Exception:
                return None
        return None
