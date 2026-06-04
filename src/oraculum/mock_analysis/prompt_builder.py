"""Build prompts for mock construction analysis."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_system_prompt(prompts_dir: str) -> str:
    """Load the mock analysis system prompt."""
    return Path(prompts_dir, "mock_analysis_system.txt").read_text(encoding="utf-8")


def build_user_prompt(
    artifact: dict[str, Any],
    classification: dict[str, Any] | None,
    source_code: str,
    prompts_dir: str,
) -> str:
    """Render the mock analysis user prompt.

    Args:
        artifact: Enriched finding artifact (from ingest).
        classification: Classification result (from classify stage).
        source_code: Target function source code.
        prompts_dir: Path to config/prompts directory.
    """
    template = Path(prompts_dir, "mock_analysis_user.txt").read_text(encoding="utf-8")

    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}

    return template.format(
        finding_json=json.dumps(artifact, indent=2, ensure_ascii=False),
        classification_json=json.dumps(
            classification or {"strategy": "unknown", "confidence": "low"},
            indent=2,
            ensure_ascii=False,
        ),
        source_code=source_code,
        function_name=function.get("name", ""),
        file_path=function.get("file", ""),
        start_line=function.get("start_line", ""),
        end_line=function.get("end_line", ""),
    )
