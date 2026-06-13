from __future__ import annotations

import json
from pathlib import Path

from oraculum.classification.runner import run_classification
from oraculum.harness.runner import run_harness
from oraculum.ingest.runner import run_ingest
from oraculum.oracle.runner import run_oracle


def _write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _make_pipeline_fixture(tmp_path: Path) -> Path:
    vhx_root = tmp_path / "VulnHunterX"
    source = vhx_root / "repos/python/demo/pkg/app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def target(value: str):\n"
        "    return value\n",
        encoding="utf-8",
    )
    output_root = vhx_root / "output/python/demo"
    (output_root / "context/functions.csv").parent.mkdir(parents=True, exist_ok=True)
    (output_root / "context/functions.csv").write_text(
        '"name","file","start_line","end_line","scope"\n'
        '"target","pkg/app.py",1,2,"Module pkg.app"\n',
        encoding="utf-8",
    )
    _write_json(
        output_root / "verification_results/summary_demo_20260613_000000.json",
        {
            "timestamp": "2026-06-13T00:00:00",
            "verdicts": [
                {
                    "finding": {
                        "rule_id": "py/xss",
                        "message": "value is returned without escaping",
                        "file": "pkg/app.py",
                        "start_line": 2,
                        "end_line": 2,
                        "repo_name": "demo",
                        "lang": "python",
                        "sarif_path": "/tmp/demo.sarif",
                        "tool": "CodeQL",
                        "dataflow_path": [],
                        "severity": "8.0",
                        "precision": "high",
                        "cwe_ids": [],
                        "tags": [],
                        "related_locations": [],
                    },
                    "verdict": "True Positive",
                    "confidence": "High",
                    "confidence_score": 0.95,
                    "reasoning": "tainted value is returned directly",
                    "answers": {"sink_identity": "return value"},
                    "context_needed": [],
                    "iterations": 1,
                    "model": "test",
                    "timestamp": "2026-06-13T00:00:00",
                    "elapsed_seconds": 1.0,
                    "tokens_used": 1,
                    "input_tokens": 1,
                    "output_tokens": 1,
                    "cached_input_tokens": 0,
                    "cost_usd": 0.0,
                    "data_flow": "value -> return",
                }
            ],
        },
    )
    return vhx_root


def test_pipeline_ingest_classify_oracle_harness(
    tmp_path: Path,
    monkeypatch,
) -> None:
    vhx_root = _make_pipeline_fixture(tmp_path)
    output_dir = tmp_path / "output"

    classification_response = json.dumps(
        {
            "schema_version": "1.0",
            "strategy": "return_value",
            "decision": {
                "q1_sink_dangerous": {"answer": False, "evidence": "return only"},
                "q2_observable_after_return": {"answer": True, "evidence": "returned value"},
                "q3_result_in_memory": {"answer": True, "evidence": "returns.kind=value"},
            },
            "mock_guidance": None,
            "confidence": "high",
            "warnings": [],
        }
    )
    oracle_response = json.dumps(
        {
            "monitor": {
                "strategy": "return_value",
                "patch_target": None,
                "target_arg_index": None,
                "target_arg_name": None,
                "capture_what": "return value",
                "additional_imports": [],
            },
            "oracle_check": {
                "condition_description": "script tag survives",
                "trigger_patterns": ["<script"],
                "raise_type": "RuntimeError",
                "raise_message_template": "XSS",
            },
            "fuzz_guidance": {"seed_corpus": ["<script>alert(1)</script>"], "skip_condition": "False"},
            "_meta": {
                "function": "target",
                "file": "pkg/app.py",
                "input_strategy": "direct_params",
                "function_signature": "def target(value: str)",
                "tainted_params": [{"name": "value", "index": 0, "type": "str"}],
            },
        }
    )
    harness_response = (
        "import atheris\n"
        "import sys\n\n"
        "def TestOneInput(data):\n"
        "    return\n\n"
        "if __name__ == \"__main__\":\n"
        "    atheris.Setup(sys.argv, TestOneInput)\n"
        "    atheris.Fuzz()\n"
    )

    monkeypatch.setattr("oraculum.classification.runner.call_llm", lambda *args, **kwargs: classification_response)
    monkeypatch.setattr("oraculum.oracle.runner.call_llm", lambda *args, **kwargs: oracle_response)
    monkeypatch.setattr("oraculum.harness.runner.call_llm", lambda *args, **kwargs: harness_response)

    ingest = run_ingest(vhx_root=vhx_root, repo="demo", output_dir=output_dir)
    classify = run_classification(repo="demo", output_dir=output_dir, model="test/model")
    oracle = run_oracle(repo="demo", output_dir=output_dir, model="test/model")
    harness = run_harness(repo="demo", output_dir=output_dir, model="test/model")

    assert ingest.ok
    assert classify.ok
    assert oracle.ok
    assert harness.ok
    target_id = "py_xss_pkg_app_py_2"
    spec = json.loads(
        (output_dir / f"python/demo/fuzz_oracles/{target_id}.json").read_text(encoding="utf-8")
    )
    assert spec["monitor"]["strategy"] == "return_value"
    assert spec["_meta"]["classification_strategy"] == "return_value"
    assert (output_dir / f"python/demo/fuzz_targets/{target_id}.py").is_file()
