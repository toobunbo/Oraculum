"""Build prompts for classification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_system_prompt(prompts_dir: Path) -> str:
    """Load the classification system prompt."""
    return (prompts_dir / "classification_system.txt").read_text(encoding="utf-8")


def build_payload(artifact: dict[str, Any], returns_signal: dict[str, Any]) -> dict[str, Any]:
    """Build the minimal classification payload from an enriched finding artifact."""
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    verification = (
        artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
    )
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}
    return {
        "rule_id": str(finding.get("rule_id") or ""),
        "function_name": str(function.get("name") or ""),
        "data_flow": verification.get("data_flow"),
        "answers": verification.get("answers"),
        "reasoning": verification.get("reasoning"),
        "returns": {
            "kind": returns_signal.get("kind", "unknown"),
            "exprs": returns_signal.get("exprs", []),
        },
    }


def build_user_prompt(payload: dict[str, Any], prompts_dir: Path) -> str:
    """Render the classification user prompt."""
    template = (prompts_dir / "classification_user.txt").read_text(encoding="utf-8")
    payload_json = json.dumps(payload, indent=2, ensure_ascii=False)
    return template.format(classification_payload_json=payload_json)
