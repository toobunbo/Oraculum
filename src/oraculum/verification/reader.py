"""Read VulnHunterX verification summaries."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERDICT_ALIASES = {
    "TP": "True Positive",
    "FP": "False Positive",
    "NMD": "Needs More Data",
    "ALL": "all",
}

VERIFICATION_KEYS = {
    "verdict",
    "confidence",
    "confidence_score",
    "reasoning",
    "answers",
    "context_needed",
    "iterations",
    "model",
    "timestamp",
    "elapsed_seconds",
    "tokens_used",
    "input_tokens",
    "output_tokens",
    "cached_input_tokens",
    "cost_usd",
    "data_flow",
}


class VerificationSummaryError(ValueError):
    """Raised when a VulnHunterX verification summary is invalid."""


def load_summary(path: Path) -> dict[str, Any]:
    """Load and validate a VulnHunterX summary JSON file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise VerificationSummaryError(f"Invalid JSON summary: {path}: {exc}") from exc
    except OSError as exc:
        raise VerificationSummaryError(f"Could not read summary: {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise VerificationSummaryError(f"Summary must be a JSON object: {path}")
    if not isinstance(data.get("verdicts"), list):
        raise VerificationSummaryError(f"Summary missing verdicts list: {path}")
    return data


def normalize_verdict_filter(verdict_filter: str) -> str:
    """Normalize a CLI verdict filter to VulnHunterX's verdict string."""
    normalized = verdict_filter.strip()
    if not normalized:
        return "True Positive"
    alias = VERDICT_ALIASES.get(normalized.upper())
    return alias or normalized


def include_verdict(item: dict[str, Any], verdict_filter: str) -> bool:
    """Return whether a VulnHunterX verdict item should be ingested."""
    verdict = item.get("verdict", "")
    if verdict == "Error":
        return False
    normalized_filter = normalize_verdict_filter(verdict_filter)
    return normalized_filter == "all" or verdict == normalized_filter


def split_verdict_item(item: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a VulnHunterX verdict item into finding and verification objects."""
    finding = item.get("finding")
    if not isinstance(finding, dict):
        raise VerificationSummaryError("Verdict item missing finding object")
    verification = {key: item[key] for key in VERIFICATION_KEYS if key in item}
    return finding, verification

