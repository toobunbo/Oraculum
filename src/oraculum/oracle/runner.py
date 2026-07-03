"""Run Oraculum oracle generation."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oraculum.oracle.llm_client import call_llm, parse_oracle_spec, validate_oracle_spec
from oraculum.oracle.paths import OraclePaths, resolve_oracle_paths, target_id_for_artifact
from oraculum.oracle.prompt_builder import build_user_prompt, load_system_prompt
from oraculum.oracle.signature_builder import (
    build_signature_from_artifact,
    get_input_strategy_from_artifact,
)


class OracleError(ValueError):
    """Raised when oracle generation cannot complete."""


@dataclass(frozen=True)
class OracleRunResult:
    """Result of an oracle generation run."""

    status_path: Path
    selected: int
    generated: int
    skipped: int
    failed: int

    @property
    def ok(self) -> bool:
        return self.failed == 0


OracleStartCallback = Callable[[int, int, dict[str, Any], Path, str], None]
OracleCompleteCallback = Callable[[int, int, dict[str, Any] | None, str, str], None]
OracleLLMCallback = Callable[[int, int, dict[str, Any], str, str, str | None], None]


def run_oracle(
    *,
    repo: str,
    lang: str = "python",
    output_dir: Path = Path("output"),
    ingest_summary: Path | None = None,
    finding_id: str | None = None,
    finding: Path | None = None,
    config_path: Path = Path("config/oracle.yaml"),
    model: str | None = None,
    force: bool = False,
    on_finding_start: OracleStartCallback | None = None,
    on_finding_complete: OracleCompleteCallback | None = None,
    on_llm_exchange: OracleLLMCallback | None = None,
) -> OracleRunResult:
    """Generate runtime oracle specs for selected enriched findings."""
    if lang != "python":
        raise OracleError(f"Only python oracle generation is currently supported, got: {lang}")

    paths = resolve_oracle_paths(output_dir=output_dir, lang=lang, repo=repo)
    config = _load_config(config_path)
    resolved_model = _resolve_model(cli_model=model, config=config)
    prompts_dir = Path(str(config.get("prompts_dir", "config/prompts"))).expanduser()

    artifacts, source_summary = _select_artifacts(
        paths=paths,
        ingest_summary=ingest_summary,
        finding_id=finding_id,
        finding=finding,
    )

    paths.fuzz_oracles_dir.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    generated = 0
    skipped = 0

    total = len(artifacts)
    for index, artifact_path in enumerate(artifacts, start=1):
        artifact: dict[str, Any] | None = None
        try:
            artifact = _load_artifact(artifact_path)
            _validate_artifact(artifact, artifact_path)
            target_id = target_id_for_artifact(artifact)
            oracle_path = paths.fuzz_oracles_dir / f"{target_id}.json"
            if on_finding_start is not None:
                on_finding_start(index, total, artifact, artifact_path, target_id)

            base_entry = _entry_base(artifact, artifact_path, oracle_path, target_id)
            if oracle_path.exists() and not force:
                skipped += 1
                entries.append({**base_entry, "status": "skipped_existing"})
                if on_finding_complete is not None:
                    on_finding_complete(index, total, artifact, "skipped_existing", str(oracle_path))
                continue

            # Load classification output JSON from repo_output / "classifications" / f"{target_id}.json"
            classifications_dir = paths.repo_output / "classifications"
            classification_path = classifications_dir / f"{target_id}.json"
            classification = None
            if classification_path.is_file():
                try:
                    classification = json.loads(classification_path.read_text(encoding="utf-8"))
                except Exception:
                    pass

            spec = _generate_spec(
                artifact=artifact,
                artifact_path=artifact_path,
                target_id=target_id,
                config=config,
                prompts_dir=prompts_dir,
                model=resolved_model,
                ollama_key_state_path=paths.output_dir / ".ollama_key_state.json",
                index=index,
                total=total,
                on_llm_exchange=on_llm_exchange,
                classification=classification,
            )
            oracle_path.write_text(
                json.dumps(spec, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            generated += 1
            strategy = spec.get("monitor", {}).get("strategy", "")
            entries.append({**base_entry, "status": "generated", "strategy": str(strategy)})
            if on_finding_complete is not None:
                on_finding_complete(index, total, artifact, "generated", str(strategy))
        except Exception as exc:
            errors.append(_error_entry(artifact_path, str(exc)))
            if artifact is not None:
                try:
                    target_id = target_id_for_artifact(artifact)
                    oracle_path = paths.fuzz_oracles_dir / f"{target_id}.json"
                    entries.append(
                        {
                            **_entry_base(artifact, artifact_path, oracle_path, target_id),
                            "status": "failed",
                        }
                    )
                except Exception:
                    pass
            if on_finding_complete is not None:
                on_finding_complete(index, total, artifact, "failed", str(exc))

    status_payload = {
        "stage": "oracle",
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
        "oracles": entries,
        "errors": errors,
    }
    paths.status_path.write_text(
        json.dumps(status_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return OracleRunResult(
        status_path=paths.status_path,
        selected=len(artifacts),
        generated=generated,
        skipped=skipped,
        failed=len(errors),
    )


def _load_config(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.expanduser().read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise OracleError(f"Could not read oracle config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise OracleError(f"Oracle config must be a mapping: {path}")
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
        raise OracleError("Oracle model is required via --model, LLM_MODEL, or config/oracle.yaml")
    return str(config_model)


def _select_artifacts(
    *,
    paths: OraclePaths,
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
        raise OracleError(f"Invalid ingest summary JSON: {summary_path}: {exc}") from exc
    except OSError as exc:
        raise OracleError(f"Could not read ingest summary: {summary_path}: {exc}") from exc

    findings = summary.get("findings")
    if not isinstance(findings, list):
        raise OracleError(f"Ingest summary missing findings list: {summary_path}")

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
        raise OracleError(f"Finding id not found in ingest summary: {finding_id}")
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
        raise OracleError(f"Invalid finding artifact JSON: {path}: {exc}") from exc
    except OSError as exc:
        raise OracleError(f"Could not read finding artifact: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise OracleError(f"Finding artifact must be a JSON object: {path}")
    return data


def _validate_artifact(artifact: dict[str, Any], path: Path) -> None:
    required_top = ("id", "rule_slug", "source", "finding", "verification", "function")
    missing_top = [field for field in required_top if field not in artifact]
    if missing_top:
        raise OracleError(f"{path} missing fields: {', '.join(missing_top)}")

    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    verification = (
        artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
    )
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}

    required_pairs = [
        (source, "source.vhx_repo_root"),
        (source, "source.vhx_output_root"),
        (finding, "finding.rule_id"),
        (finding, "finding.file"),
        (finding, "finding.start_line"),
        (verification, "verification.verdict"),
        (verification, "verification.reasoning"),
        (function, "function.name"),
    ]
    missing = [name for obj, name in required_pairs if obj.get(name.split(".", 1)[1]) in (None, "")]
    if missing:
        raise OracleError(f"{path} missing fields: {', '.join(missing)}")


def _generate_spec(
    *,
    artifact: dict[str, Any],
    artifact_path: Path,
    target_id: str,
    config: dict[str, Any],
    prompts_dir: Path,
    model: str,
    ollama_key_state_path: Path,
    index: int,
    total: int,
    on_llm_exchange: OracleLLMCallback | None,
    classification: dict[str, Any] | None = None,
) -> dict[str, Any]:
    signature = build_signature_from_artifact(artifact)
    input_strategy = get_input_strategy_from_artifact(artifact)
    verification = artifact.get("verification") if isinstance(artifact.get("verification"), dict) else {}
    answers = verification.get("answers") if isinstance(verification.get("answers"), list) else None

    strategy = classification.get("strategy") if classification else None
    system_prompt = load_system_prompt(str(prompts_dir), strategy)
    user_prompt = build_user_prompt(artifact, signature, input_strategy, str(prompts_dir), answers, classification)
    if on_llm_exchange is not None:
        on_llm_exchange(index, total, artifact, system_prompt, user_prompt, None)
    raw = call_llm(
        system_prompt,
        user_prompt,
        model,
        float(config.get("temperature", 0.0)),
        int(config.get("max_tokens", 8192)),
        int(config.get("timeout", 180)),
        ollama_key_state_path=ollama_key_state_path,
    )
    if on_llm_exchange is not None:
        on_llm_exchange(index, total, artifact, system_prompt, user_prompt, raw)
    spec = parse_oracle_spec(raw)
    _add_meta(
        spec=spec,
        artifact=artifact,
        artifact_path=artifact_path,
        target_id=target_id,
        signature=signature,
        input_strategy=input_strategy,
        model=model,
    )
    validate_oracle_spec(spec)
    return spec


def _add_meta(
    *,
    spec: dict[str, Any],
    artifact: dict[str, Any],
    artifact_path: Path,
    target_id: str,
    signature: str,
    input_strategy: str,
    model: str,
) -> None:
    finding = artifact["finding"]
    function = artifact["function"]
    meta = spec.setdefault("_meta", {})
    meta.update(
        {
            "target_id": target_id,
            "finding_id": str(artifact["id"]),
            "rule_id": finding["rule_id"],
            "rule_slug": artifact["rule_slug"],
            "file": finding["file"],
            "function": function["name"],
            "input_strategy": input_strategy,
            "function_signature": signature,
            "model": model,
            "source_finding_artifact": str(artifact_path),
        }
    )
    
    # Update tainted_params for flask_view using extracted/merged web request parameters
    web_params = artifact.get("web_params", [])
    if not web_params:
        from oraculum.oracle.signature_builder import extract_web_params_from_source
        try:
            web_params = extract_web_params_from_source(artifact)
        except Exception:
            pass

    if input_strategy == "flask_view" and web_params:
        meta["tainted_params"] = [
            {"name": p["name"], "index": -1, "type": "str"}
            for p in web_params
        ]


def _entry_base(
    artifact: dict[str, Any],
    artifact_path: Path,
    oracle_path: Path,
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
        "oracle": str(oracle_path),
    }


def _error_entry(path: Path, message: str) -> dict[str, str]:
    return {"finding_artifact": str(path), "error": message}
