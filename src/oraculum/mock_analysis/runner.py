"""Run Oraculum mock construction analysis."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oraculum.mock_analysis.llm_client import (
    call_llm,
    parse_mock_construction,
)
from oraculum.mock_analysis.paths import MockAnalysisPaths, resolve_mock_analysis_paths
from oraculum.mock_analysis.prompt_builder import build_user_prompt, load_system_prompt
from oraculum.mock_analysis.validator import MockConstructionValidationError
from oraculum.oracle.paths import target_id_for_artifact


class MockAnalysisError(ValueError):
    """Raised when mock analysis cannot complete."""


@dataclass(frozen=True)
class MockAnalysisRunResult:
    """Result of a mock analysis run."""

    status_path: Path
    selected: int
    generated: int
    skipped: int
    failed: int

    @property
    def ok(self) -> bool:
        return self.failed == 0


MockAnalysisStartCallback = Callable[[int, int, dict[str, Any], Path, str], None]
MockAnalysisCompleteCallback = Callable[[int, int, dict[str, Any] | None, str, str], None]
MockAnalysisLLMCallback = Callable[[int, int, dict[str, Any], str, str, str | None], None]


def run_mock_analysis(
    *,
    repo: str,
    lang: str = "python",
    output_dir: Path = Path("output"),
    ingest_summary: Path | None = None,
    finding_id: str | None = None,
    finding: Path | None = None,
    config_path: Path = Path("config/mock_analysis.yaml"),
    prompts_dir: Path | None = None,
    model: str | None = None,
    force: bool = False,
    on_finding_start: MockAnalysisStartCallback | None = None,
    on_finding_complete: MockAnalysisCompleteCallback | None = None,
    on_llm_exchange: MockAnalysisLLMCallback | None = None,
) -> MockAnalysisRunResult:
    """Run mock construction analysis on classified findings.

    Reads classification output, calls LLM with finding + source code,
    and writes mock_construction.json for each finding.
    """
    if lang != "python":
        raise MockAnalysisError(f"Only python mock analysis is currently supported, got: {lang}")

    paths = resolve_mock_analysis_paths(output_dir=output_dir, lang=lang, repo=repo)
    config = _load_config(config_path)
    resolved_model = _resolve_model(cli_model=model, config=config)
    prompts_dir = _resolve_prompts_dir(cli_prompts_dir=prompts_dir, config=config)

    artifacts, classifications = _select_artifacts(
        paths=paths,
        ingest_summary=ingest_summary,
        finding_id=finding_id,
        finding=finding,
    )

    paths.mock_constructions_dir.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    generated = 0
    skipped = 0

    total = len(artifacts)
    for index, artifact_path in enumerate(artifacts, start=1):
        artifact: dict[str, Any] | None = None
        try:
            artifact = _load_artifact(artifact_path)
            _validate_artifact(artifact, artifact_path)
            target_id = target_id_for_artifact(artifact)
            mc_path = paths.mock_constructions_dir / f"{target_id}.json"

            if on_finding_start is not None:
                on_finding_start(index, total, artifact, artifact_path, target_id)

            base_entry = _entry_base(artifact, artifact_path, mc_path, target_id)
            if mc_path.exists() and not force:
                skipped += 1
                entries.append({**base_entry, "status": "skipped_existing"})
                if on_finding_complete is not None:
                    on_finding_complete(
                        index, total, artifact,
                        "skipped_existing", str(mc_path),
                    )
                continue

            result = _analyze_one(
                artifact=artifact,
                artifact_path=artifact_path,
                target_id=target_id,
                classifications_dir=paths.classifications_dir,
                config=config,
                prompts_dir=prompts_dir,
                model=resolved_model,
                index=index,
                total=total,
                on_llm_exchange=on_llm_exchange,
            )

            mc_path.write_text(
                json.dumps(result, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            generated += 1
            strategy = result.get("q3_call_style", "")
            entries.append({**base_entry, "status": "generated", "strategy": strategy})
            if on_finding_complete is not None:
                on_finding_complete(
                    index, total, artifact,
                    "generated", strategy,
                )

        except Exception as exc:
            errors.append(_error_entry(artifact_path, str(exc)))
            if artifact is not None:
                try:
                    target_id = target_id_for_artifact(artifact)
                    mc_path = paths.mock_constructions_dir / f"{target_id}.json"
                    entries.append(_entry_base(artifact, artifact_path, mc_path, target_id))
                except Exception:
                    pass
            if on_finding_complete is not None:
                on_finding_complete(index, total, artifact, "failed", str(exc))

    status_payload = {
        "stage": "mock_analysis",
        "repo": repo,
        "lang": lang,
        "model": resolved_model,
        "config": str(config_path),
        "counts": {
            "selected": len(artifacts),
            "generated": generated,
            "skipped": skipped,
            "failed": len(errors),
        },
        "mock_constructions": entries,
        "errors": errors,
    }
    paths.status_path.write_text(
        json.dumps(status_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return MockAnalysisRunResult(
        status_path=paths.status_path,
        selected=len(artifacts),
        generated=generated,
        skipped=skipped,
        failed=len(errors),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_config(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.expanduser().read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise MockAnalysisError(f"Could not read mock analysis config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MockAnalysisError(f"Mock analysis config must be a mapping: {path}")
    return data


def _resolve_model(*, cli_model: str | None, config: dict[str, Any]) -> str:
    if cli_model:
        return cli_model
    provider = os.environ.get("LLM_PROVIDER")
    model_name = os.environ.get("LLM_MODEL")
    if provider and model_name:
        return f"{provider}/{model_name}"
    if model_name:
        return model_name
    config_model = config.get("model")
    if not config_model:
        raise MockAnalysisError(
            "Mock analysis model is required via --model, LLM_MODEL, or config/mock_analysis.yaml"
        )
    return str(config_model)


def _resolve_prompts_dir(cli_prompts_dir: Path | None, config: dict[str, Any]) -> Path:
    if cli_prompts_dir:
        return cli_prompts_dir.expanduser()
    prompts_dir = Path(str(config.get("prompts_dir", "config/prompts"))).expanduser()
    if prompts_dir.is_dir():
        return prompts_dir
    raise MockAnalysisError(
        f"Prompts directory not found: {prompts_dir}"
    )


def _select_artifacts(
    *,
    paths: MockAnalysisPaths,
    ingest_summary: Path | None,
    finding_id: str | None,
    finding: Path | None,
) -> tuple[list[Path], dict[str, dict[str, Any]]]:
    """Select and load artifacts with their classification results."""
    if finding is not None:
        finding = finding.expanduser()
        # Load classification if it exists
        classification = _load_classification_for_finding(paths.classifications_dir, finding)
        return [finding], classification

    summary_path = (ingest_summary or paths.repo_output / "verification_results" / "summary.json").expanduser()
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise MockAnalysisError(f"Could not read ingest summary: {summary_path}: {exc}") from exc

    findings = summary.get("findings")
    if not isinstance(findings, list):
        raise MockAnalysisError(f"Ingest summary missing findings list: {summary_path}")

    selected: list[Path] = []
    classifications: dict[str, dict[str, Any]] = {}
    for entry in findings:
        if not isinstance(entry, dict):
            continue
        if finding_id is not None and str(entry.get("id", "")) != str(finding_id):
            continue
        artifact = entry.get("artifact")
        if not artifact:
            continue

        artifact_path = _resolve_artifact_path(str(artifact), summary_path.parent)
        # Load classification
        target_id = _target_id_from_entry(entry)
        if target_id:
            classification = _load_classification(paths.classifications_dir, target_id)
            classifications[target_id] = classification
        selected.append(artifact_path)

    if finding_id is not None and not selected:
        raise MockAnalysisError(f"Finding id not found in ingest summary: {finding_id}")
    return selected, classifications


def _load_classification(classifications_dir: Path, target_id: str) -> dict[str, Any] | None:
    """Load classification JSON for a target_id, or None if not found."""
    candidate = classifications_dir / f"{target_id}.json"
    if not candidate.is_file():
        return None
    try:
        with candidate.open(encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _target_id_from_entry(entry: dict[str, Any]) -> str:
    """Extract target_id from an ingest summary entry.

    Ingest summary entries are flat (id, rule_id, file, start_line, artifact, …).
    """
    rule_id = str(entry.get("rule_id") or "unknown")
    file_path = str(entry.get("file") or "unknown")
    line = str(entry.get("start_line") or "0")
    rule_part = _slug(rule_id.replace("/", "_"))
    file_part = _slug(file_path)
    return f"{rule_part}_{file_part}_{line}"


def _slug(value: str) -> str:
    """Slugify a string to a valid filename component (mirrors oracle/paths._slug)."""
    slug = re.sub(r"[^a-zA-Z0-9]", "_", value).strip("_")
    return slug or "unknown"


def _resolve_artifact_path(raw: str, anchor: Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    candidate = anchor / raw
    if candidate.exists():
        return candidate
    return path


def _load_classification_for_finding(
    classifications_dir: Path, artifact_path: Path,
) -> dict[str, Any] | None:
    """Try to load classification result matching an artifact."""
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    finding = artifact.get("finding", {})
    rule_id = str(finding.get("rule_id") or "")
    file_path = str(finding.get("file") or "")
    line = str(finding.get("start_line") or "0")
    rule_part = _slug(rule_id.replace("/", "_"))
    file_part = _slug(file_path)
    candidate = classifications_dir / f"{rule_part}_{file_part}_{line}.json"
    if candidate.is_file():
        return json.loads(candidate.read_text(encoding="utf-8"))
    return None


def _load_artifact(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise MockAnalysisError(f"Invalid finding artifact JSON: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MockAnalysisError(f"Finding artifact must be a JSON object: {path}")
    return data


def _validate_artifact(artifact: dict[str, Any], path: Path) -> None:
    required_top = ("id", "rule_slug", "source", "finding", "verification", "function")
    missing_top = [field for field in required_top if field not in artifact]
    if missing_top:
        raise MockAnalysisError(f"{path} missing fields: {', '.join(missing_top)}")

    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    verification = (
        artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
    )
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}

    required_pairs = [
        (source, "source.vhx_repo_root"),
        (finding, "finding.rule_id"),
        (finding, "finding.file"),
        (finding, "finding.start_line"),
        (verification, "verification.reasoning"),
        (verification, "verification.data_flow"),
        (function, "function.name"),
    ]
    missing = [
        name for obj, name in required_pairs if obj.get(name.split(".", 1)[1]) in (None, "")
    ]
    if missing:
        raise MockAnalysisError(f"{path} missing fields: {', '.join(missing)}")


def _source_file_path(artifact: dict[str, Any]) -> Path | None:
    """Resolve source file path from artifact."""
    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}
    root = source.get("vhx_repo_root")
    file_path = function.get("file") or finding.get("file")
    if not root or not file_path:
        return None
    return Path(str(root)) / str(file_path)


def _analyze_one(
    *,
    artifact: dict[str, Any],
    artifact_path: Path,
    target_id: str,
    classifications_dir: Path,
    config: dict[str, Any],
    prompts_dir: Path,
    model: str,
    index: int,
    total: int,
    on_llm_exchange: MockAnalysisLLMCallback | None,
) -> dict[str, Any]:
    """Analyze mock construction for one finding."""
    source_path = _source_file_path(artifact)
    source_code = _read_source(source_path) if source_path else "(source file not available)"

    classification = _load_classification(classifications_dir, target_id)
    if classification is None:
        classification = {"strategy": "unknown", "confidence": "low", "warnings": ["no classification found"]}

    system_prompt = load_system_prompt(str(prompts_dir))
    user_prompt = build_user_prompt(
        artifact=artifact,
        classification=classification,
        source_code=source_code,
        prompts_dir=str(prompts_dir),
    )

    if on_llm_exchange is not None:
        on_llm_exchange(index, total, artifact, system_prompt, user_prompt, None)

    raw = call_llm(
        system_prompt,
        user_prompt,
        model,
        float(config.get("temperature", 0.0)),
        int(config.get("max_tokens", 4096)),
        int(config.get("timeout", 120)),
    )

    if on_llm_exchange is not None:
        on_llm_exchange(index, total, artifact, system_prompt, user_prompt, raw)

    result = parse_mock_construction(raw)
    _validate_mock_construction(result)
    return result


def _validate_mock_construction(result: dict[str, Any]) -> None:
    """Validate and normalize the mock construction result."""
    from oraculum.mock_analysis.validator import validate_mock_construction

    errors = validate_mock_construction(result)
    if errors:
        raise MockAnalysisError(f"Validation failed: {errors}")


def _read_source(path: Path) -> str:
    """Read source file content, returning fallback message on error."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return f"(source file not available: {exc})"


def _entry_base(
    artifact: dict[str, Any],
    artifact_path: Path,
    mc_path: Path,
    target_id: str,
) -> dict[str, str]:
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}
    return {
        "id": str(artifact.get("id", "")),
        "target_id": target_id,
        "rule_id": str(finding.get("rule_id", "")),
        "file": str(finding.get("file", "")),
        "start_line": str(finding.get("start_line", "")),
        "function_name": str(function.get("name", "")),
        "finding_artifact": str(artifact_path),
        "mock_construction": str(mc_path),
    }


def _error_entry(path: Path, message: str) -> dict[str, str]:
    return {"finding_artifact": str(path), "error": message}
