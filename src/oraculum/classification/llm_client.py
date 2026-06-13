"""LLM utilities and schema validation for classification."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from oraculum.llm.client import call_llm as _shared_call_llm

VALID_STRATEGIES = {"return_value", "recorded_call", "filesystem_state"}
VALID_CONFIDENCE = {"high", "medium", "low"}
DECISION_FIELDS = (
    "q1_sink_dangerous",
    "q2_observable_after_return",
    "q3_result_in_memory",
)


def call_llm(
    system_prompt: str,
    user_prompt: str,
    model: str,
    temperature: float = 0.0,
    max_tokens: int = 4096,
    timeout: int = 120,
    *,
    ollama_key_state_path: str | Path | None = None,
) -> str:
    """Call the configured LiteLLM model."""
    return _shared_call_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        ollama_key_state_path=ollama_key_state_path,
    )


def parse_classification(raw_text: str) -> dict[str, Any]:
    """Extract a JSON object from an LLM response."""
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
                    candidate = text[start:i + 1]
                    try:
                        data = json.loads(candidate)
                        if isinstance(data, dict):
                            return data
                    except json.JSONDecodeError:
                        break

    raise ValueError(f"LLM output not valid classification JSON:\n{raw_text}")


def validate_classification(spec: dict[str, Any]) -> None:
    """Validate a classification artifact from the LLM."""
    required = ("schema_version", "strategy", "decision", "mock_guidance", "confidence", "warnings")
    missing = [field for field in required if field not in spec]
    if missing:
        raise ValueError(f"classification missing fields: {', '.join(missing)}")

    if spec["schema_version"] != "1.0":
        raise ValueError("classification.schema_version must be '1.0'")

    strategy = spec["strategy"]
    if strategy not in VALID_STRATEGIES:
        raise ValueError(f"classification.strategy invalid: {strategy!r}")

    decision = spec["decision"]
    if not isinstance(decision, dict):
        raise ValueError("classification.decision must be an object")
    for field in DECISION_FIELDS:
        item = decision.get(field)
        if not isinstance(item, dict):
            raise ValueError(f"classification.decision.{field} must be an object")
        if item.get("answer") not in (True, False, None):
            raise ValueError(f"classification.decision.{field}.answer must be true, false, or null")
        if not isinstance(item.get("evidence"), str):
            raise ValueError(f"classification.decision.{field}.evidence must be a string")

    mock_guidance = spec["mock_guidance"]
    if strategy == "recorded_call":
        _validate_mock_guidance(mock_guidance)
    elif mock_guidance is not None:
        _validate_optional_mock_guidance(mock_guidance)

    if spec["confidence"] not in VALID_CONFIDENCE:
        raise ValueError("classification.confidence must be high, medium, or low")

    warnings = spec["warnings"]
    if not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings):
        raise ValueError("classification.warnings must be a list of strings")


def _validate_mock_guidance(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("classification.mock_guidance must be an object for recorded_call")
    required = ("required", "target", "capture", "fake_behavior", "notes")
    missing = [field for field in required if field not in value]
    if missing:
        raise ValueError(f"classification.mock_guidance missing fields: {', '.join(missing)}")
    if value.get("required") is not True:
        raise ValueError("classification.mock_guidance.required must be true")
    for field in ("target", "capture", "fake_behavior"):
        if not isinstance(value.get(field), str):
            raise ValueError(f"classification.mock_guidance.{field} must be a string")
    notes = value.get("notes")
    if not isinstance(notes, list) or not all(isinstance(item, str) for item in notes):
        raise ValueError("classification.mock_guidance.notes must be a list of strings")


def _validate_optional_mock_guidance(value: Any) -> None:
    if not isinstance(value, dict):
        raise ValueError("classification.mock_guidance must be an object or null")
    required = ("required", "target", "capture", "fake_behavior", "notes")
    missing = [field for field in required if field not in value]
    if missing:
        raise ValueError(f"classification.mock_guidance missing fields: {', '.join(missing)}")
    if not isinstance(value.get("required"), bool):
        raise ValueError("classification.mock_guidance.required must be a boolean")
    for field in ("target", "capture", "fake_behavior"):
        if not isinstance(value.get(field), str):
            raise ValueError(f"classification.mock_guidance.{field} must be a string")
    notes = value.get("notes")
    if not isinstance(notes, list) or not all(isinstance(item, str) for item in notes):
        raise ValueError("classification.mock_guidance.notes must be a list of strings")


def normalize_classification(spec: dict[str, Any]) -> dict[str, Any]:
    """Normalize common compact LLM outputs into the classification schema."""
    normalized = dict(spec)
    warnings = _normalized_warnings(normalized.get("warnings"))

    if "schema_version" not in normalized:
        normalized["schema_version"] = "1.0"
        warnings.append("LLM response omitted schema_version; normalized to 1.0.")

    strategy = normalized.get("strategy")
    if "decision" not in normalized:
        normalized["decision"] = _decision_from_compact_response(normalized)
        warnings.append("LLM response omitted decision; reconstructed from compact response.")
    elif isinstance(normalized["decision"], dict):
        _normalize_decision_answers(normalized["decision"])

    if "mock_guidance" not in normalized:
        normalized["mock_guidance"] = None
        warnings.append("LLM response omitted mock_guidance; normalized to null.")
    elif strategy == "recorded_call" and isinstance(normalized.get("mock_guidance"), str):
        text = normalized["mock_guidance"]
        normalized["mock_guidance"] = {
            "required": True,
            "target": text,
            "capture": text,
            "fake_behavior": (
                "Use a fake return value that lets execution continue without "
                "executing the real sink."
            ),
            "notes": ["LLM returned mock_guidance as free-form text; normalized to object."],
        }
        warnings.append("LLM response used string mock_guidance; normalized to object.")

    if "confidence" not in normalized:
        normalized["confidence"] = "low"
        warnings.append("LLM response omitted confidence; normalized to low.")

    normalized["warnings"] = warnings
    return normalized


def _normalized_warnings(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value in (None, ""):
        return []
    return [str(value)]


def _normalize_decision_answers(decision: dict[str, Any]) -> None:
    for field in DECISION_FIELDS:
        item = decision.get(field)
        if not isinstance(item, dict) or "answer" not in item:
            continue
        item["answer"] = _parse_answer(item["answer"])


def _decision_from_compact_response(spec: dict[str, Any]) -> dict[str, Any]:
    answers = spec.get("answers") if isinstance(spec.get("answers"), dict) else {}
    q1 = _answer_value(answers, "Q1", "q1", "q1_sink_dangerous")
    q2 = _answer_value(answers, "Q2", "q2", "q2_observable_after_return")
    q3 = _answer_value(answers, "Q3", "q3", "q3_result_in_memory")

    if answers:
        return {
            "q1_sink_dangerous": {
                "answer": q1,
                "evidence": _evidence_value(answers, "Q1", "q1", "q1_sink_dangerous"),
            },
            "q2_observable_after_return": {
                "answer": q2,
                "evidence": _evidence_value(answers, "Q2", "q2", "q2_observable_after_return"),
            },
            "q3_result_in_memory": {
                "answer": q3,
                "evidence": _evidence_value(answers, "Q3", "q3", "q3_result_in_memory"),
            },
        }

    strategy = spec.get("strategy")
    if strategy == "return_value":
        values = (False, True, True)
    elif strategy == "filesystem_state":
        values = (False, True, False)
    elif strategy == "recorded_call":
        values = (None, None, None)
    else:
        values = (None, None, None)

    return {
        "q1_sink_dangerous": {
            "answer": values[0],
            "evidence": "LLM did not provide Q1 evidence; reconstructed from selected strategy.",
        },
        "q2_observable_after_return": {
            "answer": values[1],
            "evidence": "LLM did not provide Q2 evidence; reconstructed from selected strategy.",
        },
        "q3_result_in_memory": {
            "answer": values[2],
            "evidence": "LLM did not provide Q3 evidence; reconstructed from selected strategy.",
        },
    }


def _answer_value(answers: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        if key in answers:
            return _parse_answer(answers[key])
    return None


def _evidence_value(answers: dict[str, Any], *keys: str) -> str:
    for key in keys:
        if key in answers:
            value = answers[key]
            return "not evaluated" if value is None else str(value)
    return "not provided"


def _parse_answer(value: Any) -> bool | None:
    if isinstance(value, bool) or value is None:
        return value
    text = str(value).strip().lower()
    if text in {"yes", "true", "1"}:
        return True
    if text in {"no", "false", "0"}:
        return False
    return None
