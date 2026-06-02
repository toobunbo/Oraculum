from __future__ import annotations

import json
from pathlib import Path

import pytest

from oraculum.classification.llm_client import (
    normalize_classification,
    parse_classification,
    validate_classification,
)
from oraculum.classification.returns import analyze_returns
from oraculum.classification.runner import run_classification
from oraculum.cli.main import main
from oraculum.ingest.runner import run_ingest


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_functions_csv(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                '"name","file","start_line","end_line","scope"',
                '"target","pkg/app.py",1,2,"Module pkg.app"',
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _make_vhx_fixture(tmp_path: Path) -> Path:
    vhx_root = tmp_path / "VulnHunterX"
    source = vhx_root / "repos/python/demo/pkg/app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def target(value: str):\n"
        "    open(value, 'w').write('x')\n",
        encoding="utf-8",
    )

    output_root = vhx_root / "output/python/demo"
    _write_functions_csv(output_root / "context/functions.csv")
    summary = {
        "timestamp": "2026-05-23T00:00:00",
        "verdicts": [
            {
                "finding": {
                    "rule_id": "py/path-injection",
                    "message": "user-controlled path reaches open",
                    "file": "pkg/app.py",
                    "start_line": 2,
                    "end_line": 2,
                    "repo_name": "demo",
                    "lang": "python",
                    "sarif_path": "/tmp/demo.sarif",
                    "tool": "CodeQL",
                    "dataflow_path": [],
                    "severity": "9.1",
                    "precision": "high",
                    "cwe_ids": [],
                    "tags": [],
                    "related_locations": [],
                },
                "verdict": "True Positive",
                "confidence": "High",
                "confidence_score": 0.95,
                "reasoning": "value flows to open without path validation",
                "answers": {
                    "sink_identity": "open() receives a path derived from user input",
                    "sanitization_absent": "No path normalization or prefix check is applied",
                    "exploit_possible": "../ can escape the intended directory",
                },
                "context_needed": [],
                "iterations": 1,
                "model": "glm-5.1",
                "timestamp": "2026-05-23T00:00:00",
                "elapsed_seconds": 1.0,
                "tokens_used": 10,
                "input_tokens": 7,
                "output_tokens": 3,
                "cached_input_tokens": 0,
                "cost_usd": 0.0,
                "data_flow": "value -> open(value, 'w')",
            }
        ],
    }
    _write_json(output_root / "verification_results/summary_demo_20260523_000000.json", summary)
    return vhx_root


def _recorded_response() -> str:
    return json.dumps(
        {
            "schema_version": "1.0",
            "strategy": "recorded_call",
            "decision": {
                "q1_sink_dangerous": {
                    "answer": True,
                    "evidence": "open is called in write mode with a user-controlled path",
                },
                "q2_observable_after_return": {
                    "answer": None,
                    "evidence": "not evaluated because Q1 selected recorded_call",
                },
                "q3_result_in_memory": {
                    "answer": None,
                    "evidence": "not evaluated because Q1 selected recorded_call",
                },
            },
            "mock_guidance": {
                "required": True,
                "target": "patch the open call as used by the target module",
                "capture": "capture the path argument passed to open",
                "fake_behavior": "return a MagicMock with write support",
                "notes": ["do not write real files during fuzzing"],
            },
            "confidence": "high",
            "warnings": [],
        }
    )


def test_classification_generates_from_ingest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr(
        "oraculum.classification.runner.call_llm",
        lambda *args, **kwargs: _recorded_response(),
    )

    result = run_classification(repo="demo", output_dir=output_dir, model="test/model")

    assert result.ok
    assert result.selected == 1
    assert result.generated == 1
    target_id = "py_path_injection_pkg_app_py_2"
    classification_path = output_dir / f"python/demo/classifications/{target_id}.json"
    assert classification_path.is_file()

    spec = json.loads(classification_path.read_text(encoding="utf-8"))
    assert spec["strategy"] == "recorded_call"
    assert spec["mock_guidance"]["required"] is True

    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["counts"] == {"selected": 1, "generated": 1, "skipped": 0, "failed": 0}
    assert status["classifications"][0]["target_id"] == target_id
    assert status["classifications"][0]["strategy"] == "recorded_call"


def test_classification_prompt_preserves_answers_dict_and_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    captured: dict[str, str] = {}

    def fake_call(_system: str, user: str, *_args, **_kwargs) -> str:
        captured["user"] = user
        return _recorded_response()

    monkeypatch.setattr("oraculum.classification.runner.call_llm", fake_call)

    run_classification(repo="demo", output_dir=output_dir, model="test/model")

    assert '"answers": {' in captured["user"]
    assert '"sink_identity": "open() receives a path derived from user input"' in captured["user"]
    assert '"returns": {' in captured["user"]
    assert '"kind": "none"' in captured["user"]


def test_classification_skips_existing_without_force(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr(
        "oraculum.classification.runner.call_llm",
        lambda *args, **kwargs: _recorded_response(),
    )

    run_classification(repo="demo", output_dir=output_dir, model="test/model")
    result = run_classification(repo="demo", output_dir=output_dir, model="test/model")

    assert result.ok
    assert result.generated == 0
    assert result.skipped == 1
    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["classifications"][0]["status"] == "skipped_existing"
    assert status["classifications"][0]["strategy"] == "recorded_call"


def test_classification_cli_writes_markdown_log(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    log_file = tmp_path / "classification.md"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr(
        "oraculum.classification.runner.call_llm",
        lambda *args, **kwargs: _recorded_response(),
    )

    rc = main(
        [
            "classify",
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
    assert "# Oraculum Classification Run" in log_text
    assert "### System Prompt" in log_text
    assert "### User Prompt" in log_text
    assert "### LLM Response (Iteration 1)" in log_text
    assert "Classification Input" in log_text
    assert '"strategy": "recorded_call"' in log_text


def test_parse_classification_extracts_fenced_json() -> None:
    parsed = parse_classification(f"```json\n{_recorded_response()}\n```")

    assert parsed["strategy"] == "recorded_call"


def test_normalize_classification_accepts_compact_model_response() -> None:
    compact = {
        "strategy": "recorded_call",
        "confidence": "high",
        "answers": {"Q1": "YES", "Q2": None, "Q3": None},
        "mock_guidance": "Mock parseString and capture the XML argument.",
    }

    normalized = normalize_classification(compact)
    validate_classification(normalized)

    assert normalized["schema_version"] == "1.0"
    assert normalized["decision"]["q1_sink_dangerous"]["answer"] is True
    assert normalized["mock_guidance"]["required"] is True
    assert "normalized" in " ".join(normalized["warnings"])


def test_validate_classification_rejects_invalid_strategy() -> None:
    spec = json.loads(_recorded_response())
    spec["strategy"] = "patch_call"

    with pytest.raises(ValueError, match="strategy invalid"):
        validate_classification(spec)


def test_validate_classification_rejects_return_value_with_mock_guidance() -> None:
    spec = json.loads(_recorded_response())
    spec["strategy"] = "return_value"

    with pytest.raises(ValueError, match="mock_guidance must be null"):
        validate_classification(spec)


def test_validate_classification_rejects_recorded_call_without_mock_guidance() -> None:
    spec = json.loads(_recorded_response())
    spec["mock_guidance"] = None

    with pytest.raises(ValueError, match="mock_guidance must be an object"):
        validate_classification(spec)


def test_returns_analyzer_value_none_and_mixed(tmp_path: Path) -> None:
    source_root = tmp_path / "repo"
    source = source_root / "pkg/app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def returns_value(x):\n"
        "    return x\n\n"
        "def returns_none(x):\n"
        "    return None\n\n"
        "def returns_mixed(x):\n"
        "    if not x:\n"
        "        return None\n"
        "    def nested():\n"
        "        return 'nested'\n"
        "    return response\n",
        encoding="utf-8",
    )

    def artifact(name: str, start: int, end: int) -> dict:
        return {
            "source": {"vhx_repo_root": str(source_root)},
            "finding": {"file": "pkg/app.py"},
            "function": {"name": name, "file": "pkg/app.py", "start_line": start, "end_line": end},
        }

    assert analyze_returns(artifact("returns_value", 1, 2)) == {"kind": "value", "exprs": ["x"]}
    assert analyze_returns(artifact("returns_none", 4, 5)) == {"kind": "none", "exprs": []}
    assert analyze_returns(artifact("returns_mixed", 7, 12)) == {
        "kind": "mixed",
        "exprs": ["None", "response"],
    }
