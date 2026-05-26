"""Path resolution for Oraculum oracle generation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class OraclePathError(ValueError):
    """Raised when oracle input or output paths cannot be resolved."""


@dataclass(frozen=True)
class OraclePaths:
    """Resolved paths for one repo's oracle stage."""

    output_dir: Path
    lang: str
    repo: str
    repo_output: Path
    verification_dir: Path
    default_ingest_summary_path: Path
    fuzz_oracles_dir: Path
    status_path: Path


def resolve_oracle_paths(*, output_dir: Path, lang: str, repo: str) -> OraclePaths:
    """Resolve default oracle paths for one repository."""
    output_dir = output_dir.expanduser()
    repo_output = output_dir / lang / repo
    verification_dir = repo_output / "verification_results"
    fuzz_oracles_dir = repo_output / "fuzz_oracles"
    return OraclePaths(
        output_dir=output_dir,
        lang=lang,
        repo=repo,
        repo_output=repo_output,
        verification_dir=verification_dir,
        default_ingest_summary_path=verification_dir / "summary.json",
        fuzz_oracles_dir=fuzz_oracles_dir,
        status_path=fuzz_oracles_dir / "status.json",
    )


def target_id_for_artifact(artifact: dict[str, Any]) -> str:
    """Return the VulnHunterX-style fuzz target basename for an enriched finding."""
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    rule_id = str(finding.get("rule_id") or artifact.get("rule_slug") or "unknown")
    file_path = str(finding.get("file") or "unknown")
    line = str(finding.get("start_line") or "0")
    rule_part = _slug(rule_id.replace("/", "_"))
    file_part = _slug(file_path)
    return f"{rule_part}_{file_part}_{line}"


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]", "_", value).strip("_")
    return slug or "unknown"
