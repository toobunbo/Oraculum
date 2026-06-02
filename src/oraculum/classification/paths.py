"""Path resolution for Oraculum classification."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClassificationPaths:
    """Resolved paths for one repo's classification stage."""

    output_dir: Path
    lang: str
    repo: str
    repo_output: Path
    verification_dir: Path
    default_ingest_summary_path: Path
    classifications_dir: Path
    status_path: Path


def resolve_classification_paths(
    *,
    output_dir: Path,
    lang: str,
    repo: str,
) -> ClassificationPaths:
    """Resolve default classification paths for one repository."""
    output_dir = output_dir.expanduser()
    repo_output = output_dir / lang / repo
    verification_dir = repo_output / "verification_results"
    classifications_dir = repo_output / "classifications"
    return ClassificationPaths(
        output_dir=output_dir,
        lang=lang,
        repo=repo,
        repo_output=repo_output,
        verification_dir=verification_dir,
        default_ingest_summary_path=verification_dir / "summary.json",
        classifications_dir=classifications_dir,
        status_path=classifications_dir / "status.json",
    )
