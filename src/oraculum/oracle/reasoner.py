"""Backward-compatible single-finding oracle entrypoint."""

from __future__ import annotations

import json
from pathlib import Path

from oraculum.oracle.paths import target_id_for_artifact
from oraculum.oracle.runner import run_oracle


def run(finding_path: str, config_path: str = "config/oracle.yaml") -> dict:
    """Generate one oracle spec from an enriched finding artifact."""
    path = Path(finding_path)
    artifact = json.loads(path.read_text(encoding="utf-8"))
    finding = artifact["finding"]
    repo = finding["repo_name"]
    lang = finding["lang"]
    output_dir = _infer_output_dir(path, lang, repo)

    run_oracle(
        repo=repo,
        lang=lang,
        output_dir=output_dir,
        finding=path,
        config_path=Path(config_path),
        force=True,
    )

    oracle_path = output_dir / lang / repo / "fuzz_oracles" / f"{target_id_for_artifact(artifact)}.json"
    return json.loads(oracle_path.read_text(encoding="utf-8"))


def _infer_output_dir(path: Path, lang: str, repo: str) -> Path:
    """Infer output root from output/<lang>/<repo>/verification_results/findings/*.json."""
    resolved = path.expanduser().resolve()
    parts = resolved.parts
    suffix = (lang, repo, "verification_results", "findings")
    for idx in range(len(parts) - len(suffix) + 1):
        if tuple(parts[idx : idx + len(suffix)]) == suffix:
            return Path(*parts[:idx])
    return Path("output")
