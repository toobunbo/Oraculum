"""LLM utilities for mock construction analysis."""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any


def call_llm(
    system_prompt: str,
    user_prompt: str,
    model: str,
    temperature: float = 0.0,
    max_tokens: int = 4096,
    timeout: int = 120,
) -> str:
    """Call the configured LiteLLM model."""
    _silence_litellm_optional_provider_warnings()
    from litellm import completion

    logging.debug("\n========== MOCK ANALYSIS LLM REQUEST ==========")
    logging.debug("[SYSTEM PROMPT]\n%s\n", system_prompt)
    logging.debug("[USER PROMPT]\n%s\n", user_prompt)

    response = completion(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )

    content = response.choices[0].message.content
    logging.debug(
        "========== MOCK ANALYSIS LLM RESPONSE ==========\n%s\n"
        "==================================",
        content,
    )
    return content


def _silence_litellm_optional_provider_warnings() -> None:
    """Suppress noisy LiteLLM warnings for optional providers we do not use."""
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    for logger_name in ("LiteLLM", "litellm"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)


def parse_mock_construction(raw_text: str) -> dict[str, Any]:
    """Extract a JSON object from an LLM mock construction response."""
    text = raw_text.strip()
    fence = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if fence:
        candidate = fence.group(1).strip()
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    start = text.find("{")
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start : i + 1]
                    try:
                        data = json.loads(candidate)
                        if isinstance(data, dict):
                            return data
                    except json.JSONDecodeError:
                        break

    raise ValueError(f"LLM output not valid mock_construction JSON:\n{raw_text}")
