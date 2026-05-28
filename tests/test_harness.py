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
        "decision": {
            "q1_sink_dangerous": True,
            "q1_reason": "open may touch filesystem",
            "q2_observable_after_return": False,
            "q2_reason": "violation is observed at sink call",
            "q3_accessible_in_memory": None,
            "q3_reason": None,
            "build_mock": True,
            "oracle_approach": "recorded_call",
            "confidence": "high",
        },
        "research": {
            "target_to_record": "pkg.app.open",
            "target_arg_index": 0,
            "record_selector": None,
            "fake_return": "readable file mock",
            "return_selector": None,
            "filesystem_watch": {"allowed_root": None, "snapshot_dirs": []},
            "assertion": {
                "kind": "regex_match",
                "input": "captured",
                "patterns": [r"\.\./"],
                "description": "path traversal reaches open",
            },
            "additional_imports": [],
            "risks": [],
        },
        "oracle_check": {
            "condition_description": "path traversal reaches open",
            "trigger_patterns": [r"\.\./"],
            "raise_type": "RuntimeError",
            "raise_message_template": "PATH_INJECTION: captured={captured}",
        },
        "fuzz_guidance": {
            "seed_corpus": ["../etc/passwd", "../../secret.txt"],
            "skip_condition": "False",
        },
        "driver": {
            "arrange": {"tainted_params": [], "setup": [], "skip_condition": "False"},
            "act": {"target_callable": "target", "call_style": "direct"},
            "assert": {"place": "after_target_call", "input": "recorded_call", "never_assert_on": "raw fuzz input"},
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
                "oracle_approach": "recorded_call",
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
    assert "security fuzzing engineer" in log_text
    assert "Fill ONLY the" in log_text
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
