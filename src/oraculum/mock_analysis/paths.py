"""Path resolution for Oraculum mock construction analysis."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class MockAnalysisPaths:
    """Resolved paths for one repo's mock analysis stage."""

    output_dir: Path
    lang: str
    repo: str
    repo_output: Path
    classifications_dir: Path
    mock_constructions_dir: Path
    status_path: Path


def resolve_mock_analysis_paths(
    *,
    output_dir: Path,
    lang: str,
    repo: str,
) -> MockAnalysisPaths:
    """Resolve default mock analysis paths for one repository."""
    output_dir = output_dir.expanduser()
    repo_output = output_dir / lang / repo
    classifications_dir = repo_output / "classifications"
    mock_constructions_dir = repo_output / "mock_constructions"
    return MockAnalysisPaths(
        output_dir=output_dir,
        lang=lang,
        repo=repo,
        repo_output=repo_output,
        classifications_dir=classifications_dir,
        mock_constructions_dir=mock_constructions_dir,
        status_path=mock_constructions_dir / "status.json",
    )
