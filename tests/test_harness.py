from __future__ import annotations

import json
from pathlib import Path

import pytest

from oraculum.cli.main import main
from oraculum.harness.llm_client import extract_code, validate_harness
from oraculum.harness.runner import run_harness


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _make_harness_fixture(tmp_path: Path) -> Path:
    output_dir = tmp_path / "output"
    source_root = tmp_path / "VulnHunterX/repos/python/demo"
    source = source_root / "pkg/app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def target(value: str):\n"
        "    return open(value).read()\n",
        encoding="utf-8",
    )

    target_id = "py_path_injection_pkg_app_py_2"
    artifact_path = (
        output_dir
        / "python/demo/verification_results/findings/finding_0_py_path-injection.json"
    )
    oracle_path = output_dir / f"python/demo/fuzz_oracles/{target_id}.json"
    artifact = {
        "id": "0",
        "rule_slug": "py_path_injection",
        "source": {
            "vhx_repo_root": str(source_root),
            "vhx_output_root": str(tmp_path / "VulnHunterX/output/python/demo"),
        },
        "finding": {
            "rule_id": "py/path-injection",
            "message": "user-controlled path reaches open",
            "file": "pkg/app.py",
            "start_line": 2,
            "end_line": 2,
            "repo_name": "demo",
            "lang": "python",
        },
        "verification": {
            "verdict": "True Positive",
            "reasoning": "value flows to open without validation",
        },
        "function": {
            "name": "target",
            "start_line": 1,
            "end_line": 2,
            "scope": "Module pkg.app",
        },
    }
    oracle = {
        "monitor": {
            "strategy": "recorded_call",
            "patch_target": "pkg.app.open",
            "target_arg_index": 0,
            "target_arg_name": None,
            "capture_what": "path passed to open",
            "additional_imports": [],
        },
        "oracle_check": {
            "condition_description": "path traversal reaches open",
            "trigger_patterns": [r"\.\./"],
            "raise_type": "RuntimeError",
            "raise_message_template": "PATH_INJECTION: captured={captured}",
        },
        "fuzz_guidance": {
            "seed_corpus": ["../etc/passwd", "../../secret.txt"],
            "skip_condition": "'../' not in value",
        },
        "_meta": {
            "target_id": target_id,
            "finding_id": "0",
            "rule_id": "py/path-injection",
            "rule_slug": "py_path_injection",
            "file": "pkg/app.py",
            "function": "target",
            "input_strategy": "direct_params",
            "function_signature": "def target(value: str)",
            "tainted_params": [{"name": "value", "index": 0, "type": "str"}],
            "source_finding_artifact": str(artifact_path),
        },
    }
    status = {
        "stage": "oracle",
        "repo": "demo",
        "lang": "python",
        "counts": {"selected": 1, "generated": 1, "skipped": 0, "failed": 0},
        "oracles": [
            {
                "id": "0",
                "target_id": target_id,
                "rule_id": "py/path-injection",
                "file": "pkg/app.py",
                "start_line": "2",
                "function_name": "target",
                "finding_artifact": str(artifact_path),
                "oracle": str(oracle_path),
                "status": "generated",
                "strategy": "recorded_call",
            }
        ],
        "errors": [],
    }
    _write_json(artifact_path, artifact)
    _write_json(oracle_path, oracle)
    _write_json(output_dir / "python/demo/fuzz_oracles/status.json", status)
    return output_dir


def _harness_response() -> str:
    return """```python
import atheris
import sys

def TestOneInput(data):
    return

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```"""


def test_harness_generates_targets_and_corpus(tmp_path: Path, monkeypatch) -> None:
    output_dir = _make_harness_fixture(tmp_path)
    monkeypatch.setattr("oraculum.harness.runner.call_llm", lambda *args, **kwargs: _harness_response())

    result = run_harness(repo="demo", output_dir=output_dir, model="test/model")

    assert result.ok
    assert result.selected == 1
    assert result.generated == 1
    target_id = "py_path_injection_pkg_app_py_2"
    harness_path = output_dir / f"python/demo/fuzz_targets/{target_id}.py"
    corpus_dir = output_dir / f"python/demo/fuzz_corpus/{target_id}"
    assert harness_path.is_file()
    assert (corpus_dir / "seed_000").read_text(encoding="utf-8") == "../etc/passwd"
    assert (corpus_dir / "seed_001").read_text(encoding="utf-8") == "../../secret.txt"

    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["counts"] == {"selected": 1, "generated": 1, "skipped": 0, "failed": 0}
    assert status["harnesses"][0]["target_id"] == target_id
    assert status["harnesses"][0]["status"] == "generated"


def test_harness_skips_existing_without_force(tmp_path: Path, monkeypatch) -> None:
    output_dir = _make_harness_fixture(tmp_path)
    monkeypatch.setattr("oraculum.harness.runner.call_llm", lambda *args, **kwargs: _harness_response())

    run_harness(repo="demo", output_dir=output_dir, model="test/model")
    result = run_harness(repo="demo", output_dir=output_dir, model="test/model")

    assert result.ok
    assert result.generated == 0
    assert result.skipped == 1
    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["harnesses"][0]["status"] == "skipped_existing"


def test_harness_cli_writes_markdown_log(tmp_path: Path, monkeypatch, capsys) -> None:
    output_dir = _make_harness_fixture(tmp_path)
    log_file = tmp_path / "harness.md"
    monkeypatch.setattr("oraculum.harness.runner.call_llm", lambda *args, **kwargs: _harness_response())

    rc = main(
        [
            "harness",
            "--repo",
            "demo",
            "--lang",
            "python",
            "--output-dir",
            str(output_dir),
            "--model",
            "test/model",
            "--log-file",
            str(log_file),
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert "Done. selected=1 generated=1 skipped=0 failed=0" in captured.out
    assert f"Log: {log_file}" in captured.out
    log_text = log_file.read_text(encoding="utf-8")
    assert "# Oraculum Harness Run" in log_text
    assert "## [1/1] py/path-injection" in log_text
    assert "### System Prompt" in log_text
    assert "### User Prompt" in log_text
    assert "### LLM Response (Iteration 1)" in log_text
    assert "expert security fuzzing engineer" in log_text
    assert "Complete the following partial Atheris harness" in log_text
    assert "atheris.Setup" in log_text


def test_harness_marks_empty_llm_response_failed(tmp_path: Path, monkeypatch) -> None:
    output_dir = _make_harness_fixture(tmp_path)
    monkeypatch.setattr("oraculum.harness.runner.call_llm", lambda *args, **kwargs: "")

    result = run_harness(repo="demo", output_dir=output_dir, model="test/model")

    assert not result.ok
    assert result.generated == 0
    assert result.failed == 1
    target_id = "py_path_injection_pkg_app_py_2"
    assert not (output_dir / f"python/demo/fuzz_targets/{target_id}.py").exists()
    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["harnesses"][0]["status"] == "failed"
    assert "empty Python harness" in status["harnesses"][0]["errors"]


def test_harness_validation_rejects_incomplete_fenced_skeleton() -> None:
    code = extract_code(
        "```python\n"
        "import atheris\n"
        "# copied prompt fragment, no completed harness\n"
    )

    assert code.startswith("import atheris")
    with pytest.raises(ValueError, match="missing TestOneInput"):
        validate_harness(code)


def test_harness_generates_filesystem_state_skeleton() -> None:
    from oraculum.harness.template_builder import build_skeleton
    
    artifact = {
        "id": "1",
        "rule_slug": "py_path_traversal",
        "source": {
            "vhx_repo_root": "/tmp/dummy",
        },
        "finding": {
            "rule_id": "py/path-traversal",
            "message": "untrusted input is written to file",
            "file": "pkg/writer.py",
            "start_line": 5,
            "end_line": 5,
        },
        "verification": {
            "verdict": "True Positive",
            "reasoning": "untrusted input goes directly to write",
        },
        "function": {
            "name": "write_data",
            "start_line": 1,
            "end_line": 6,
        },
    }
    
    oracle_spec = {
        "monitor": {
            "strategy": "filesystem_state",
            "patch_target": None,
            "target_arg_index": None,
            "target_arg_name": None,
            "capture_what": "files written outside path",
            "additional_imports": [],
        },
        "oracle_check": {
            "condition_description": "writes outside path",
            "trigger_patterns": [],
            "raise_type": "RuntimeError",
            "raise_message_template": "TRAVERSAL: file written outside boundary",
        },
        "fuzz_guidance": {
            "seed_corpus": ["../passwd"],
            "skip_condition": "False",
        },
        "_meta": {
            "target_id": "py_path_traversal_pkg_writer_py_5",
            "finding_id": "1",
            "rule_id": "py/path-traversal",
            "rule_slug": "py_path_traversal",
            "file": "pkg/writer.py",
            "function": "write_data",
            "input_strategy": "direct_params",
            "function_signature": "def write_data(path: str, data: str)",
            "tainted_params": [
                {"name": "path", "index": 0, "type": "str"},
                {"name": "data", "index": 1, "type": "str"},
            ],
            "source_finding_artifact": "dummy_path",
        },
    }
    
    skeleton = build_skeleton(
        artifact=artifact,
        spec=oracle_spec,
        repo_root="/tmp/dummy",
        corpus_dir="/tmp/dummy/corpus",
    )
    
    assert "import tempfile" in skeleton
    assert "import shutil" in skeleton
    assert "=== FILESYSTEM_STATE SKELETON ===" in skeleton
    assert "tempfile.TemporaryDirectory" in skeleton


def test_harness_loader_loads_all_prompts(tmp_path: Path) -> None:
    from oraculum.harness.runner import _load_system_prompt
    
    prompts_dir = tmp_path / "prompts"
    prompts_dir.mkdir()
    (prompts_dir / "harness_system_recorded_call.txt").write_text("recorded_call_content", encoding="utf-8")
    (prompts_dir / "harness_system_return_value.txt").write_text("return_value_content", encoding="utf-8")
    (prompts_dir / "harness_system_filesystem_state.txt").write_text("filesystem_state_content", encoding="utf-8")
    
    p1 = _load_system_prompt(prompts_dir, {"monitor": {"strategy": "recorded_call"}})
    p2 = _load_system_prompt(prompts_dir, {"monitor": {"strategy": "return_value"}})
    p3 = _load_system_prompt(prompts_dir, {"monitor": {"strategy": "filesystem_state"}})
    p4 = _load_system_prompt(prompts_dir, {})  # should default to return_value
    
    assert p1 == "recorded_call_content"
    assert p2 == "return_value_content"
    assert p3 == "filesystem_state_content"
    assert p4 == "return_value_content"
