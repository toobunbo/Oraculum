from __future__ import annotations

import json
from pathlib import Path

from oraculum.cli.main import main
from oraculum.ingest.runner import run_ingest
from oraculum.oracle.runner import run_oracle
from oraculum.oracle.signature_builder import (
    build_signature_from_artifact,
    get_input_strategy_from_artifact,
)


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _write_functions_csv(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                '"name","file","start_line","end_line","scope"',
                '"target","pkg/app.py",1,5,"Module pkg.app"',
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
        "    return open(value).read()\n",
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
                "reasoning": "value flows to open without validation",
                "answers": ["tainted value reaches open path argument"],
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
                "data_flow": "value -> open",
            }
        ],
    }
    _write_json(output_root / "verification_results/summary_demo_20260523_000000.json", summary)
    return vhx_root


def _oracle_response() -> str:
    return json.dumps(
        {
            "monitor": {
                "strategy": "patch_call",
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
                "raise_message_template": "PATH_INJECTION: captured={captured} pattern={matched_pattern}",
            },
            "fuzz_guidance": {
                "seed_corpus": ["../etc/passwd", "../../secret.txt", "../tmp/demo"],
                "skip_condition": "'../' not in value",
            },
            "_meta": {
                "function": "target",
                "file": "pkg/app.py",
                "input_strategy": "direct_params",
                "function_signature": "def target(value: str)",
                "tainted_params": [{"name": "value", "index": 0, "type": "str"}],
            },
        }
    )


def test_oracle_generates_fuzz_oracles_from_ingest(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr("oraculum.oracle.runner.call_llm", lambda *args, **kwargs: _oracle_response())

    result = run_oracle(repo="demo", output_dir=output_dir, model="test/model")

    assert result.ok
    assert result.selected == 1
    assert result.generated == 1
    target_id = "py_path_injection_pkg_app_py_2"
    oracle_path = output_dir / f"python/demo/fuzz_oracles/{target_id}.json"
    assert oracle_path.is_file()

    spec = json.loads(oracle_path.read_text(encoding="utf-8"))
    assert spec["_meta"]["target_id"] == target_id
    assert spec["_meta"]["function_signature"] == "def target(value: str)"
    assert spec["_meta"]["source_finding_artifact"].endswith(
        "python/demo/verification_results/findings/finding_0_py_path-injection.json"
    )

    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["counts"] == {"selected": 1, "generated": 1, "skipped": 0, "failed": 0}
    assert status["oracles"][0]["target_id"] == target_id
    assert status["oracles"][0]["status"] == "generated"


def test_oracle_skips_existing_without_force(tmp_path: Path, monkeypatch) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr("oraculum.oracle.runner.call_llm", lambda *args, **kwargs: _oracle_response())

    run_oracle(repo="demo", output_dir=output_dir, model="test/model")
    result = run_oracle(repo="demo", output_dir=output_dir, model="test/model")

    assert result.ok
    assert result.generated == 0
    assert result.skipped == 1
    status = json.loads(result.status_path.read_text(encoding="utf-8"))
    assert status["oracles"][0]["status"] == "skipped_existing"


def test_oracle_cli_smoke(tmp_path: Path, monkeypatch, capsys) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr("oraculum.oracle.runner.call_llm", lambda *args, **kwargs: _oracle_response())

    rc = main(
        [
            "oracle",
            "--repo",
            "demo",
            "--lang",
            "python",
            "--output-dir",
            str(output_dir),
            "--model",
            "test/model",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert "Done. selected=1 generated=1 skipped=0 failed=0" in captured.out
    assert (output_dir / "python/demo/fuzz_oracles/status.json").is_file()


def test_oracle_cli_writes_markdown_log(tmp_path: Path, monkeypatch, capsys) -> None:
    vhx_root = _make_vhx_fixture(tmp_path)
    output_dir = tmp_path / "output"
    log_file = tmp_path / "oracle.md"
    run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    monkeypatch.setattr("oraculum.oracle.runner.call_llm", lambda *args, **kwargs: _oracle_response())

    rc = main(
        [
            "oracle",
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
    assert f"Log: {log_file}" in captured.out
    log_text = log_file.read_text(encoding="utf-8")
    assert "# Oraculum Oracle Run" in log_text
    assert "## [1/1] py/path-injection" in log_text
    assert "### System Prompt" in log_text
    assert "### User Prompt" in log_text
    assert "### LLM Response (Iteration 1)" in log_text
    assert "You are a fuzzing oracle designer" in log_text
    assert "user-controlled path reaches open" in log_text
    assert '"strategy": "patch_call"' in log_text
    assert "- Result: `generated`" in log_text
    assert "## Summary" in log_text


def test_oracle_signature_uses_flask_view_for_no_param_functions(tmp_path: Path) -> None:
    source_root = tmp_path / "repo"
    source = source_root / "pkg/app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def view():\n"
        "    return request.headers.get('x')\n",
        encoding="utf-8",
    )
    artifact = {
        "source": {"vhx_repo_root": str(source_root)},
        "finding": {"file": "pkg/app.py"},
        "function": {"name": "view", "start_line": 1, "end_line": 2, "scope": "Module pkg.app"},
    }

    assert build_signature_from_artifact(artifact) == "def view()"
    assert get_input_strategy_from_artifact(artifact) == "flask_view"
