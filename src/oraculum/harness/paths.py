"""Path resolution for Oraculum harness generation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class HarnessPaths:
    """Resolved paths for one repo's harness stage."""

    output_dir: Path
    lang: str
    repo: str
    repo_output: Path
    fuzz_oracles_dir: Path
    default_oracle_status_path: Path
    fuzz_targets_dir: Path
    fuzz_corpus_dir: Path
    status_path: Path


def resolve_harness_paths(*, output_dir: Path, lang: str, repo: str) -> HarnessPaths:
    """Resolve default harness paths for one repository."""
    output_dir = output_dir.expanduser()
    repo_output = output_dir / lang / repo
    fuzz_oracles_dir = repo_output / "fuzz_oracles"
    fuzz_targets_dir = repo_output / "fuzz_targets"
    fuzz_corpus_dir = repo_output / "fuzz_corpus"
    return HarnessPaths(
        output_dir=output_dir,
        lang=lang,
        repo=repo,
        repo_output=repo_output,
        fuzz_oracles_dir=fuzz_oracles_dir,
        default_oracle_status_path=fuzz_oracles_dir / "status.json",
        fuzz_targets_dir=fuzz_targets_dir,
        fuzz_corpus_dir=fuzz_corpus_dir,
        status_path=fuzz_targets_dir / "status.json",
    )
