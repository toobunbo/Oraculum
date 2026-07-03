"""Path resolution for Oraculum ingest."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


class IngestPathError(ValueError):
    """Raised when required ingest paths cannot be resolved."""


@dataclass(frozen=True)
class IngestPaths:
    """Resolved VulnHunterX and Oraculum paths for one repo ingest."""

    vhx_root: Path
    lang: str
    repo: str
    output_dir: Path
    vhx_repo_root: Path
    vhx_output_root: Path
    vhx_verification_dir: Path
    vhx_context_dir: Path
    vhx_functions_csv: Path
    vhx_web_params_csv: Path
    summary_path: Path
    repo_output: Path
    ingest_dir: Path
    ingest_findings_dir: Path
    ingest_summary_path: Path


def resolve_ingest_paths(
    *,
    vhx_root: Path,
    lang: str,
    repo: str,
    output_dir: Path,
    summary: Path | None = None,
) -> IngestPaths:
    """Resolve all paths needed by ingest."""
    vhx_root = vhx_root.expanduser().resolve()
    output_dir = output_dir.expanduser()
    if not vhx_root.is_dir():
        raise IngestPathError(f"VulnHunterX root not found: {vhx_root}")

    vhx_repo_root = vhx_root / "repos" / lang / repo
    vhx_output_root = vhx_root / "output" / lang / repo
    vhx_verification_dir = vhx_output_root / "verification_results"
    vhx_context_dir = vhx_output_root / "context"
    vhx_functions_csv = vhx_context_dir / "functions.csv"
    vhx_web_params_csv = vhx_context_dir / "web_params.csv"

    if not vhx_output_root.is_dir():
        raise IngestPathError(f"VulnHunterX repo output not found: {vhx_output_root}")
    if not vhx_verification_dir.is_dir():
        raise IngestPathError(f"Verification results not found: {vhx_verification_dir}")

    summary_path = resolve_summary_path(
        summary=summary,
        vhx_root=vhx_root,
        verification_dir=vhx_verification_dir,
        repo=repo,
    )

    repo_output = output_dir / lang / repo
    ingest_dir = repo_output / "verification_results"
    ingest_findings_dir = ingest_dir / "findings"
    ingest_summary_path = ingest_dir / "summary.json"

    return IngestPaths(
        vhx_root=vhx_root,
        lang=lang,
        repo=repo,
        output_dir=output_dir,
        vhx_repo_root=vhx_repo_root,
        vhx_output_root=vhx_output_root,
        vhx_verification_dir=vhx_verification_dir,
        vhx_context_dir=vhx_context_dir,
        vhx_functions_csv=vhx_functions_csv,
        vhx_web_params_csv=vhx_web_params_csv,
        summary_path=summary_path,
        repo_output=repo_output,
        ingest_dir=ingest_dir,
        ingest_findings_dir=ingest_findings_dir,
        ingest_summary_path=ingest_summary_path,
    )


def resolve_summary_path(
    *,
    summary: Path | None,
    vhx_root: Path,
    verification_dir: Path,
    repo: str,
) -> Path:
    """Resolve explicit summary or select the newest summary for repo."""
    if summary is not None:
        candidates = []
        raw = summary.expanduser()
        if raw.is_absolute():
            candidates.append(raw)
        else:
            candidates.append(Path.cwd() / raw)
            candidates.append(vhx_root / raw)
        for candidate in candidates:
            if candidate.is_file():
                return candidate.resolve()
        candidate_list = ", ".join(str(path) for path in candidates)
        raise IngestPathError(f"Summary not found. Tried: {candidate_list}")

    summaries = sorted(verification_dir.glob(f"summary_{repo}_*.json"))
    if not summaries:
        raise IngestPathError(f"No summary_{repo}_*.json found in {verification_dir}")
    return max(summaries, key=_summary_sort_key).resolve()


def _summary_sort_key(path: Path) -> tuple[str, float]:
    match = re.search(r"summary_.+_(\d{8}_\d{6})\.json$", path.name)
    timestamp = match.group(1) if match else ""
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    return timestamp, mtime


def rule_slug(rule_id: str) -> str:
    """Return stable rule slug for artifact names."""
    return rule_id.replace("/", "_") or "unknown"
