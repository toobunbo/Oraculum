"""Run Oraculum harness generation."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from oraculum.harness.llm_client import call_llm, extract_code, validate_harness
from oraculum.harness.paths import HarnessPaths, resolve_harness_paths
from oraculum.harness.template_builder import build_skeleton
from oraculum.oracle.llm_client import validate_oracle_spec
from oraculum.oracle.paths import target_id_for_artifact


class HarnessError(ValueError):
    """Raised when harness generation cannot complete."""


@dataclass(frozen=True)
class HarnessRunResult:
    """Result of a harness generation run."""

    status_path: Path
    selected: int
    generated: int
    skipped: int
    failed: int

    @property
    def ok(self) -> bool:
        return self.failed == 0


@dataclass(frozen=True)
class HarnessTarget:
    """One selected oracle and finding pair."""

    target_id: str
    oracle_path: Path
    finding_artifact_path: Path
    status_entry: dict[str, Any]


HarnessStartCallback = Callable[
    [int, int, dict[str, Any], dict[str, Any], str, Path, Path, Path],
    None,
]
HarnessCompleteCallback = Callable[[int, int, dict[str, Any] | None, str, str], None]
HarnessLLMCallback = Callable[
    [int, int, dict[str, Any], dict[str, Any], str, str, str | None],
    None,
]


def run_harness(
    *,
    repo: str,
    lang: str = "python",
    output_dir: Path = Path("output"),
    oracle_status: Path | None = None,
    target_id: str | None = None,
    finding_id: str | None = None,
    oracle: Path | None = None,
    config_path: Path = Path("config/harness.yaml"),
    model: str | None = None,
    force: bool = False,
    on_harness_start: HarnessStartCallback | None = None,
    on_harness_complete: HarnessCompleteCallback | None = None,
    on_llm_exchange: HarnessLLMCallback | None = None,
) -> HarnessRunResult:
    """Generate Atheris fuzz harnesses for selected oracle specs."""
    if lang != "python":
        raise HarnessError(f"Only python harness generation is currently supported, got: {lang}")

    paths = resolve_harness_paths(output_dir=output_dir, lang=lang, repo=repo)
    config = _load_config(config_path)
    resolved_model = _resolve_model(cli_model=model, config=config)
    prompts_dir = Path(str(config.get("prompts_dir", "config/prompts"))).expanduser()

    targets, source_status = _select_targets(
        paths=paths,
        oracle_status=oracle_status,
        target_id=target_id,
        finding_id=finding_id,
        oracle=oracle,
    )

    paths.fuzz_targets_dir.mkdir(parents=True, exist_ok=True)
    paths.fuzz_corpus_dir.mkdir(parents=True, exist_ok=True)

    entries: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    generated = 0
    skipped = 0

    total = len(targets)
    for index, target in enumerate(targets, start=1):
        artifact: dict[str, Any] | None = None
        try:
            oracle_spec = _load_json_object(target.oracle_path, "oracle JSON")
            validate_oracle_spec(oracle_spec)
            artifact = _load_json_object(target.finding_artifact_path, "finding artifact")
            _validate_artifact(artifact, target.finding_artifact_path)

            effective_target_id = _resolve_target_id(target, oracle_spec, artifact)
            harness_path = paths.fuzz_targets_dir / f"{effective_target_id}.py"
            corpus_dir = paths.fuzz_corpus_dir / effective_target_id
            base_entry = _entry_base(
                target_id=effective_target_id,
                target=target,
                artifact=artifact,
                oracle_spec=oracle_spec,
                harness_path=harness_path,
                corpus_dir=corpus_dir,
            )

            if on_harness_start is not None:
                on_harness_start(
                    index,
                    total,
                    artifact,
                    oracle_spec,
                    effective_target_id,
                    target.oracle_path,
                    harness_path,
                    corpus_dir,
                )

            if harness_path.exists() and not force:
                skipped += 1
                entries.append({**base_entry, "status": "skipped_existing", "errors": ""})
                if on_harness_complete is not None:
                    on_harness_complete(index, total, artifact, "skipped_existing", str(harness_path))
                continue

            code = _generate_harness_code(
                artifact=artifact,
                oracle_spec=oracle_spec,
                corpus_dir=corpus_dir,
                config=config,
                prompts_dir=prompts_dir,
                model=resolved_model,
                ollama_key_state_path=paths.output_dir / ".ollama_key_state.json",
                index=index,
                total=total,
                on_llm_exchange=on_llm_exchange,
            )
            harness_path.write_text(code, encoding="utf-8")
            seed_count = _write_seed_corpus(oracle_spec, corpus_dir)

            generated += 1
            strategy = str(oracle_spec.get("monitor", {}).get("strategy", ""))
            entries.append(
                {
                    **base_entry,
                    "status": "generated",
                    "strategy": strategy,
                    "seed_count": seed_count,
                    "errors": "",
                }
            )
            if on_harness_complete is not None:
                on_harness_complete(index, total, artifact, "generated", str(harness_path))
        except Exception as exc:
            errors.append(
                {
                    "target_id": target.target_id,
                    "oracle": str(target.oracle_path),
                    "finding_artifact": str(target.finding_artifact_path),
                    "error": str(exc),
                }
            )
            entries.append(_failed_entry(target, artifact, str(exc), paths))
            if on_harness_complete is not None:
                on_harness_complete(index, total, artifact, "failed", str(exc))

    status_payload = {
        "stage": "harness",
        "repo": repo,
        "lang": lang,
        "model": resolved_model,
        "config": str(config_path),
        "source": {"oracle_status_path": str(source_status) if source_status else ""},
        "counts": {
            "selected": len(targets),
            "generated": generated,
            "skipped": skipped,
            "failed": len(errors),
        },
        "harnesses": entries,
        "errors": errors,
    }
    paths.status_path.write_text(
        json.dumps(status_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return HarnessRunResult(
        status_path=paths.status_path,
        selected=len(targets),
        generated=generated,
        skipped=skipped,
        failed=len(errors),
    )


def generate_one_harness(
    *,
    artifact: dict[str, Any],
    oracle_spec: dict[str, Any],
    corpus_dir: Path,
    config: dict[str, Any],
    prompts_dir: Path,
    model: str,
) -> str:
    """Generate and validate one harness source string."""
    return _generate_harness_code(
        artifact=artifact,
        oracle_spec=oracle_spec,
        corpus_dir=corpus_dir,
        config=config,
        prompts_dir=prompts_dir,
        model=model,
        ollama_key_state_path=Path("output") / ".ollama_key_state.json",
        index=1,
        total=1,
        on_llm_exchange=None,
    )


def _load_config(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.expanduser().read_text(encoding="utf-8")) or {}
    except OSError as exc:
        raise HarnessError(f"Could not read harness config: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HarnessError(f"Harness config must be a mapping: {path}")
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
        raise HarnessError("Harness model is required via --model, LLM_MODEL, or config/harness.yaml")
    return str(config_model)


def _select_targets(
    *,
    paths: HarnessPaths,
    oracle_status: Path | None,
    target_id: str | None,
    finding_id: str | None,
    oracle: Path | None,
) -> tuple[list[HarnessTarget], Path | None]:
    if oracle is not None:
        target = _target_from_explicit_oracle(oracle.expanduser())
        if target_id is not None and target.target_id != target_id:
            raise HarnessError(
                f"Explicit oracle target_id mismatch: expected {target_id}, got {target.target_id}"
            )
        if finding_id is not None and str(target.status_entry.get("id", "")) != str(finding_id):
            raise HarnessError(
                f"Explicit oracle finding id mismatch: expected {finding_id}, "
                f"got {target.status_entry.get('id', '')}"
            )
        return [target], None

    status_path = (oracle_status or paths.default_oracle_status_path).expanduser()
    status = _load_json_object(status_path, "oracle status")
    raw_entries = status.get("oracles")
    if not isinstance(raw_entries, list):
        raise HarnessError(f"Oracle status missing oracles list: {status_path}")

    selected: list[HarnessTarget] = []
    for entry in raw_entries:
        if not isinstance(entry, dict):
            continue
        if entry.get("status") != "generated":
            continue
        if target_id is not None and str(entry.get("target_id", "")) != str(target_id):
            continue
        if finding_id is not None and str(entry.get("id", "")) != str(finding_id):
            continue
        selected.append(_target_from_status_entry(entry, status_path))

    if target_id is not None and not selected:
        raise HarnessError(f"Target id not found in oracle status: {target_id}")
    if finding_id is not None and not selected:
        raise HarnessError(f"Finding id not found in oracle status: {finding_id}")
    return selected, status_path


def _target_from_explicit_oracle(oracle_path: Path) -> HarnessTarget:
    spec = _load_json_object(oracle_path, "oracle JSON")
    meta = spec.get("_meta") if isinstance(spec.get("_meta"), dict) else {}
    target_id = str(meta.get("target_id") or "")
    finding_artifact = str(meta.get("source_finding_artifact") or "")
    if not target_id:
        raise HarnessError(f"Explicit oracle missing _meta.target_id: {oracle_path}")
    if not finding_artifact:
        raise HarnessError(f"Explicit oracle missing _meta.source_finding_artifact: {oracle_path}")
    status_entry = {
        "id": str(meta.get("finding_id", "")),
        "target_id": target_id,
        "rule_id": str(meta.get("rule_id", "")),
        "file": str(meta.get("file", "")),
        "start_line": str(meta.get("start_line", "")),
        "function_name": str(meta.get("function", "")),
        "oracle": str(oracle_path),
        "finding_artifact": finding_artifact,
    }
    return HarnessTarget(
        target_id=target_id,
        oracle_path=oracle_path,
        finding_artifact_path=_resolve_path(finding_artifact, oracle_path),
        status_entry=status_entry,
    )


def _target_from_status_entry(entry: dict[str, Any], status_path: Path) -> HarnessTarget:
    target_id = str(entry.get("target_id") or "")
    oracle = str(entry.get("oracle") or "")
    finding_artifact = str(entry.get("finding_artifact") or "")
    missing = []
    if not target_id:
        missing.append("target_id")
    if not oracle:
        missing.append("oracle")
    if not finding_artifact:
        missing.append("finding_artifact")
    if missing:
        raise HarnessError(f"Oracle status entry missing fields: {', '.join(missing)}")
    return HarnessTarget(
        target_id=target_id,
        oracle_path=_resolve_path(oracle, status_path),
        finding_artifact_path=_resolve_path(finding_artifact, status_path),
        status_entry=entry,
    )


def _resolve_path(raw: str, anchor: Path) -> Path:
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path
    if path.exists():
        return path
    candidate = anchor.parent / path
    if candidate.exists():
        return candidate
    return path


def _load_json_object(path: Path, description: str) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HarnessError(f"Invalid {description}: {path}: {exc}") from exc
    except OSError as exc:
        raise HarnessError(f"Could not read {description}: {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HarnessError(f"{description.capitalize()} must be a JSON object: {path}")
    return data


def _validate_artifact(artifact: dict[str, Any], path: Path) -> None:
    required_top = ("id", "rule_slug", "source", "finding", "verification", "function")
    missing_top = [field for field in required_top if field not in artifact]
    if missing_top:
        raise HarnessError(f"{path} missing fields: {', '.join(missing_top)}")

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
        (verification, "verification.verdict"),
        (verification, "verification.reasoning"),
        (function, "function.name"),
    ]
    missing = [name for obj, name in required_pairs if obj.get(name.split(".", 1)[1]) in (None, "")]
    if missing:
        raise HarnessError(f"{path} missing fields: {', '.join(missing)}")


def _resolve_target_id(
    target: HarnessTarget,
    oracle_spec: dict[str, Any],
    artifact: dict[str, Any],
) -> str:
    meta = oracle_spec.get("_meta") if isinstance(oracle_spec.get("_meta"), dict) else {}
    meta_target_id = str(meta.get("target_id") or "")
    artifact_target_id = target_id_for_artifact(artifact)
    if meta_target_id and meta_target_id != target.target_id:
        raise HarnessError(
            f"Oracle target_id mismatch: status has {target.target_id}, spec has {meta_target_id}"
        )
    if artifact_target_id != target.target_id:
        raise HarnessError(
            f"Finding target_id mismatch: status has {target.target_id}, "
            f"artifact resolves to {artifact_target_id}"
        )
    return target.target_id


def _generate_harness_code(
    *,
    artifact: dict[str, Any],
    oracle_spec: dict[str, Any],
    corpus_dir: Path,
    config: dict[str, Any],
    prompts_dir: Path,
    model: str,
    ollama_key_state_path: Path,
    index: int,
    total: int,
    on_llm_exchange: HarnessLLMCallback | None,
) -> str:
    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    repo_root = str(source.get("vhx_repo_root") or "")
    skeleton = build_skeleton(
        artifact,
        oracle_spec,
        repo_root=repo_root,
        corpus_dir=str(corpus_dir),
    )
    system_prompt = _load_system_prompt(prompts_dir, oracle_spec)
    user_prompt = _load_user_prompt(prompts_dir).format(skeleton=skeleton)
    if on_llm_exchange is not None:
        on_llm_exchange(index, total, artifact, oracle_spec, system_prompt, user_prompt, None)
    raw = call_llm(
        system_prompt,
        user_prompt,
        model,
        float(config.get("temperature", 0.15)),
        int(config.get("max_tokens", 8192)),
        int(config.get("timeout", 120)),
        ollama_key_state_path=ollama_key_state_path,
    )
    if on_llm_exchange is not None:
        on_llm_exchange(index, total, artifact, oracle_spec, system_prompt, user_prompt, raw)
    code = extract_code(raw)
    validate_harness(code)
    return code


def _load_system_prompt(prompts_dir: Path, oracle_spec: dict[str, Any]) -> str:
    strategy = str(oracle_spec.get("monitor", {}).get("strategy") or "inspect_return")
    if strategy == "patch_call":
        filename = "harness_system_patch_call.txt"
    else:
        filename = "harness_system_inspect_return.txt"
    return (prompts_dir / filename).read_text(encoding="utf-8")


def _load_user_prompt(prompts_dir: Path) -> str:
    return (prompts_dir / "harness_user.txt").read_text(encoding="utf-8")


def _write_seed_corpus(oracle_spec: dict[str, Any], corpus_dir: Path) -> int:
    fuzz_guidance = (
        oracle_spec.get("fuzz_guidance")
        if isinstance(oracle_spec.get("fuzz_guidance"), dict)
        else {}
    )
    seeds = fuzz_guidance.get("seed_corpus")
    if not isinstance(seeds, list):
        return 0
    corpus_dir.mkdir(parents=True, exist_ok=True)
    for index, seed in enumerate(seeds):
        (corpus_dir / f"seed_{index:03d}").write_bytes(str(seed).encode("utf-8", errors="replace"))
    return len(seeds)


def _entry_base(
    *,
    target_id: str,
    target: HarnessTarget,
    artifact: dict[str, Any],
    oracle_spec: dict[str, Any],
    harness_path: Path,
    corpus_dir: Path,
) -> dict[str, Any]:
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}
    monitor = oracle_spec.get("monitor") if isinstance(oracle_spec.get("monitor"), dict) else {}
    return {
        "id": str(artifact.get("id", target.status_entry.get("id", ""))),
        "target_id": target_id,
        "rule_id": str(finding.get("rule_id", target.status_entry.get("rule_id", ""))),
        "file": str(finding.get("file", target.status_entry.get("file", ""))),
        "start_line": str(finding.get("start_line", target.status_entry.get("start_line", ""))),
        "function_name": str(function.get("name", target.status_entry.get("function_name", ""))),
        "harness": str(harness_path),
        "oracle": str(target.oracle_path),
        "finding_artifact": str(target.finding_artifact_path),
        "corpus": str(corpus_dir),
        "strategy": str(monitor.get("strategy", target.status_entry.get("strategy", ""))),
    }


def _failed_entry(
    target: HarnessTarget,
    artifact: dict[str, Any] | None,
    error: str,
    paths: HarnessPaths,
) -> dict[str, Any]:
    target_id = target.target_id or str(target.status_entry.get("target_id", "unknown"))
    finding = artifact.get("finding") if isinstance(artifact, dict) else {}
    function = artifact.get("function") if isinstance(artifact, dict) else {}
    return {
        "id": str((artifact or {}).get("id", target.status_entry.get("id", ""))),
        "target_id": target_id,
        "rule_id": str(finding.get("rule_id", target.status_entry.get("rule_id", ""))),
        "file": str(finding.get("file", target.status_entry.get("file", ""))),
        "start_line": str(finding.get("start_line", target.status_entry.get("start_line", ""))),
        "function_name": str(function.get("name", target.status_entry.get("function_name", ""))),
        "harness": str(paths.fuzz_targets_dir / f"{target_id}.py"),
        "oracle": str(target.oracle_path),
        "finding_artifact": str(target.finding_artifact_path),
        "corpus": str(paths.fuzz_corpus_dir / target_id),
        "status": "failed",
        "errors": error,
    }
