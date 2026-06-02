"""Run Oraculum classification."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oraculum.classification.llm_client import (
    call_llm,
    normalize_classification,
    parse_classification,
    validate_classification,
)
from oraculum.classification.paths import (
    ClassificationPaths,
    resolve_classification_paths,
)
from oraculum.classification.prompt_builder import (
    build_payload,
    build_user_prompt,
    load_system_prompt,
)
from oraculum.classification.returns import analyze_returns
from oraculum.oracle.paths import target_id_for_artifact


class ClassificationError(ValueError):
    """Raised when classification cannot complete."""


@dataclass(frozen=True)
class ClassificationRunResult:
    """Result of a classification run."""

    status_path: Path
    selected: int
    generated: int
    skipped: int
    failed: int
    model: str

    @property
    def ok(self) -> bool:
        return self.failed == 0


ClassificationStartCallback = Callable[[int, int, dict[str, Any], Path, str], None]
ClassificationCompleteCallback = Callable[[int, int, dict[str, Any] | None, str, str], None]
ClassificationLLMCallback = Callable[[int, int, dict[str, Any], str, str, str | None], None]


def run_classification(
    *,
    repo: str,
    lang: str = "python",
    output_dir: Path = Path("output"),
    ingest_summary: Path | None = None,
    finding_id: str | None = None,
    finding: Path | None = None,
    config_path: Path = Path("config/classification.yaml"),
    model: str | None = None,
    force: bool = False,
    on_finding_start: ClassificationStartCallback | None = None,
    on_finding_complete: ClassificationCompleteCallback | None = None,
    on_llm_exchange: ClassificationLLMCallback | None = None,
) -> ClassificationRunResult:
    """Classify selected enriched findings into runtime oracle strategies."""
    if lang != "python":
        raise ClassificationError(f"Only python classification is currently supported, got: {lang}")

    paths = resolve_classification_paths(output_dir=output_dir, lang=lang, repo=repo)
    config = _load_config(config_path)
    resolved_model = _resolve_model(cli_model=model, config=config)
    prompts_dir = Path(str(config.get("prompts_dir", "config/prompts"))).expanduser()

    artifacts, source_summary = _select_artifacts(
        paths=paths,
        ingest_summary=ingest_summary,
        finding_id=finding_id,
        finding=finding,
    )

    paths.classifications_dir.mkdir(parents=True, exist_ok=True)

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
            classification_path = paths.classifications_dir / f"{target_id}.json"
            base_entry = _entry_base(artifact, artifact_path, classification_path, target_id)

            if on_finding_start is not None:
                on_finding_start(index, total, artifact, artifact_path, target_id)

            if classification_path.exists() and not force:
                skipped += 1
                entries.append(
                    {
                        **base_entry,
                        **_existing_classification_fields(classification_path),
                        "status": "skipped_existing",
                    }
                )
                if on_finding_complete is not None:
                    on_finding_complete(
                        index,
                        total,
                        artifact,
                        "skipped_existing",
                        str(classification_path),
                    )
                continue

            spec = _generate_classification(
                artifact=artifact,
                config=config,
                prompts_dir=prompts_dir,
                model=resolved_model,
                index=index,
                total=total,
                on_llm_exchange=on_llm_exchange,
            )
            classification_path.write_text(
                json.dumps(spec, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            generated += 1
            strategy = str(spec.get("strategy", ""))
            confidence = str(spec.get("confidence", ""))
            entries.append(
                {
                    **base_entry,
                    "status": "generated",
                    "strategy": strategy,
                    "confidence": confidence,
                }
            )
            if on_finding_complete is not None:
                on_finding_complete(index, total, artifact, "generated", strategy)
        except Exception as exc:
            errors.append(_error_entry(artifact_path, str(exc)))
            if artifact is not None:
                try:
                    target_id = target_id_for_artifact(artifact)
                    classification_path = paths.classifications_dir / f"{target_id}.json"
                    entries.append(
                        {
                            **_entry_base(artifact, artifact_path, classification_path, target_id),
                            "status": "failed",
                            "errors": str(exc),
                        }
                    )
                except Exception:
                    pass
            if on_finding_complete is not None:
                on_finding_complete(index, total, artifact, "failed", str(exc))

    status_payload = {
        "stage": "classification",
        "repo": repo,
        "lang": lang,
        "model": resolved_model,
        "config": str(config_path),
        "source": {"ingest_summary_path": str(source_summary) if source_summary else ""},
        "counts": {
            "selected": len(artifacts),
            "generated": generated,
            "skipped": skipped,
            "failed": len(errors),
        },
        "classifications": entries,
        "errors": errors,
    }
    paths.status_path.write_text(
        json.dumps(status_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return ClassificationRunResult(
        status_path=paths.status_path,
        selected=len(artifacts),
        generated=generated,
        skipped=skipped,
        failed=len(errors),
        model=resolved_model,
    )


def _load_config(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.expanduser().read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise ClassificationError(f"Could not read classification config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ClassificationError(f"Classification config must be a mapping: {path}")
    return data


def _resolve_model(*, cli_model: str | None, config: dict[str, Any]) -> str:
    if cli_model:
        return cli_model
    provider = os.environ.get("LLM_PROVIDER")
    model = os.environ.get("LLM_MODEL")
    if provider and model:
        return f"{provider}/{model}"
    if model:
        return model
    config_model = config.get("model")
    if not config_model:
        raise ClassificationError(
            "Classification model is required via --model, LLM_MODEL, or "
            "config/classification.yaml"
        )
    return str(config_model)


def _select_artifacts(
    *,
    paths: ClassificationPaths,
    ingest_summary: Path | None,
    finding_id: str | None,
    finding: Path | None,
) -> tuple[list[Path], Path | None]:
    if finding is not None:
        return [finding.expanduser()], None

    summary_path = (ingest_summary or paths.default_ingest_summary_path).expanduser()
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ClassificationError(f"Invalid ingest summary JSON: {summary_path}: {exc}") from exc
    except OSError as exc:
        raise ClassificationError(f"Could not read ingest summary: {summary_path}: {exc}") from exc

    findings = summary.get("findings")
    if not isinstance(findings, list):
        raise ClassificationError(f"Ingest summary missing findings list: {summary_path}")

    selected: list[Path] = []
    for entry in findings:
        if not isinstance(entry, dict):
            continue
        if finding_id is not None and str(entry.get("id", "")) != str(finding_id):
            continue
        artifact = entry.get("artifact")
        if not artifact:
            continue
        selected.append(_resolve_artifact_path(str(artifact), summary_path))

    if finding_id is not None and not selected:
        raise ClassificationError(f"Finding id not found in ingest summary: {finding_id}")
    return selected, summary_path


def _resolve_artifact_path(raw: str, summary_path: Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    candidate = summary_path.parent / path
    if candidate.exists():
        return candidate
    return path


def _load_artifact(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ClassificationError(f"Invalid finding artifact JSON: {path}: {exc}") from exc
    except OSError as exc:
        raise ClassificationError(f"Could not read finding artifact: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ClassificationError(f"Finding artifact must be a JSON object: {path}")
    return data


def _validate_artifact(artifact: dict[str, Any], path: Path) -> None:
    required_top = ("id", "rule_slug", "source", "finding", "verification", "function")
    missing_top = [field for field in required_top if field not in artifact]
    if missing_top:
        raise ClassificationError(f"{path} missing fields: {', '.join(missing_top)}")

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
    missing = [name for obj, name in required_pairs if obj.get(name.split(".", 1)[1]) in (None, "")]
    if missing:
        raise ClassificationError(f"{path} missing fields: {', '.join(missing)}")


def _generate_classification(
    *,
    artifact: dict[str, Any],
    config: dict[str, Any],
    prompts_dir: Path,
    model: str,
    index: int,
    total: int,
    on_llm_exchange: ClassificationLLMCallback | None,
) -> dict[str, Any]:
    returns_signal = analyze_returns(artifact)
    payload = build_payload(artifact, returns_signal)
    system_prompt = load_system_prompt(prompts_dir)
    user_prompt = build_user_prompt(payload, prompts_dir)
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
    spec = normalize_classification(parse_classification(raw))
    validate_classification(spec)
    return spec


def _entry_base(
    artifact: dict[str, Any],
    artifact_path: Path,
    classification_path: Path,
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
        "classification": str(classification_path),
    }


def _existing_classification_fields(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(data, dict):
        return {}
    return {
        "strategy": str(data.get("strategy", "")),
        "confidence": str(data.get("confidence", "")),
    }


def _error_entry(path: Path, message: str) -> dict[str, str]:
    return {"finding_artifact": str(path), "error": message}
