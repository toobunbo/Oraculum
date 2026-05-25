"""Run Oraculum ingest."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from oraculum.context.functions import (
    FunctionInfo,
    find_enclosing_function,
    load_functions_csv,
)
from oraculum.ingest.paths import IngestPaths, resolve_ingest_paths, rule_slug
from oraculum.verification.reader import (
    include_verdict,
    load_summary,
    normalize_verdict_filter,
    split_verdict_item,
)

REQUIRED_FINDING_FIELDS = ("rule_id", "file", "start_line", "repo_name", "lang")


class IngestError(ValueError):
    """Raised when ingest cannot complete."""


@dataclass(frozen=True)
class IngestRunResult:
    """Result of an ingest run."""

    summary_path: Path
    source_summary_path: Path
    selected: int
    enriched: int
    skipped: int
    failed: int

    @property
    def ok(self) -> bool:
        return self.failed == 0


def run_ingest(
    *,
    vhx_root: Path,
    repo: str,
    lang: str = "python",
    summary: Path | None = None,
    verdict_filter: str = "TP",
    output_dir: Path = Path("output"),
    force: bool = False,
) -> IngestRunResult:
    """Import VulnHunterX verification results into Oraculum."""
    if lang != "python":
        raise IngestError(f"Only python ingest is currently supported, got: {lang}")

    paths = resolve_ingest_paths(
        vhx_root=vhx_root,
        lang=lang,
        repo=repo,
        output_dir=output_dir,
        summary=summary,
    )
    if paths.ingest_summary_path.exists() and not force:
        raise IngestError(
            f"Ingest summary already exists: {paths.ingest_summary_path}. Use --force to overwrite."
        )

    source_summary = load_summary(paths.summary_path)
    functions = load_functions_csv(paths.vhx_functions_csv)
    verdicts = source_summary["verdicts"]
    normalized_filter = normalize_verdict_filter(verdict_filter)

    paths.ingest_findings_dir.mkdir(parents=True, exist_ok=True)

    finding_entries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    selected_count = 0
    enriched_count = 0
    skipped_count = 0

    for idx, item in enumerate(verdicts):
        if not isinstance(item, dict):
            skipped_count += 1
            errors.append({"id": str(idx), "error": "Verdict item is not an object"})
            continue

        if not include_verdict(item, normalized_filter):
            skipped_count += 1
            continue

        selected_count += 1
        try:
            finding, verification = split_verdict_item(item)
            _validate_finding(finding, idx)
            function = _enrich_function(functions, finding, idx)
            artifact_path = _write_enriched_finding(
                paths=paths,
                idx=idx,
                finding=finding,
                verification=verification,
                function=function,
            )
            enriched_count += 1
            finding_entries.append(
                {
                    "id": str(idx),
                    "rule_id": finding.get("rule_id", ""),
                    "verdict": item.get("verdict", ""),
                    "artifact": str(artifact_path),
                    "function_name": function.name,
                }
            )
        except Exception as exc:
            errors.append(_error_entry(idx, item, str(exc)))

    summary_payload = {
        "stage": "ingest",
        "repo": repo,
        "lang": lang,
        "verdict_filter": verdict_filter,
        "normalized_verdict_filter": normalized_filter,
        "source": _source_metadata(paths),
        "counts": {
            "total_verdicts": len(verdicts),
            "selected": selected_count,
            "enriched": enriched_count,
            "skipped": skipped_count,
            "failed": len(errors),
        },
        "findings": finding_entries,
        "errors": errors,
    }

    paths.ingest_dir.mkdir(parents=True, exist_ok=True)
    paths.ingest_summary_path.write_text(
        json.dumps(summary_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return IngestRunResult(
        summary_path=paths.ingest_summary_path,
        source_summary_path=paths.summary_path,
        selected=selected_count,
        enriched=enriched_count,
        skipped=skipped_count,
        failed=len(errors),
    )


def _validate_finding(finding: dict[str, Any], idx: int) -> None:
    missing = [field for field in REQUIRED_FINDING_FIELDS if finding.get(field) in (None, "")]
    if missing:
        raise IngestError(f"finding {idx} missing required fields: {', '.join(missing)}")
    try:
        int(finding["start_line"])
    except (TypeError, ValueError) as exc:
        raise IngestError(f"finding {idx} has invalid start_line: {finding.get('start_line')}") from exc


def _enrich_function(
    functions: list[FunctionInfo],
    finding: dict[str, Any],
    idx: int,
) -> FunctionInfo:
    function = find_enclosing_function(
        functions,
        file_path=str(finding["file"]),
        start_line=int(finding["start_line"]),
    )
    if function is None:
        raise IngestError(
            "No enclosing function found for "
            f"finding {idx}: {finding.get('rule_id', '')} "
            f"@ {finding.get('file', '')}:{finding.get('start_line', '')}"
        )
    return function


def _write_enriched_finding(
    *,
    paths: IngestPaths,
    idx: int,
    finding: dict[str, Any],
    verification: dict[str, Any],
    function: FunctionInfo,
) -> Path:
    slug = rule_slug(str(finding.get("rule_id", "")))
    artifact_path = paths.ingest_findings_dir / f"finding_{idx}_{slug}.json"
    payload = {
        "id": str(idx),
        "rule_slug": slug,
        "source": _source_metadata(paths),
        "finding": finding,
        "verification": verification,
        "function": function.to_dict(),
    }
    artifact_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return artifact_path


def _source_metadata(paths: IngestPaths) -> dict[str, str]:
    return {
        "vhx_root": str(paths.vhx_root),
        "vhx_repo_root": str(paths.vhx_repo_root),
        "vhx_output_root": str(paths.vhx_output_root),
        "summary_path": str(paths.summary_path),
    }


def _error_entry(idx: int, item: dict[str, Any], message: str) -> dict[str, Any]:
    finding = item.get("finding") if isinstance(item.get("finding"), dict) else {}
    return {
        "id": str(idx),
        "rule_id": finding.get("rule_id", ""),
        "file": finding.get("file", ""),
        "start_line": finding.get("start_line", ""),
        "error": message,
    }
