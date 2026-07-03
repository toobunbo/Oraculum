from __future__ import annotations

import csv
import json
from pathlib import Path
import pytest

from oraculum.oracle.csv_loader import load_web_params, WebParamRow
from oraculum.oracle.signature_builder import (
    extract_web_params_from_source,
    merge_web_params,
    get_input_strategy_from_artifact,
)

@pytest.fixture
def sample_flask_file(tmp_path) -> Path:
    source_file = tmp_path / "app.py"
    source_file.write_text(
        "from flask import request\n"
        "\n"
        "def view_get():\n"
        "    expr = request.args.get('expr')\n"
        "    template = request.args.get('template')\n"
        "    return eval(expr)\n"
        "\n"
        "def view_subscript():\n"
        "    val = request.form['payload']\n"
        "    return exec(val)\n"
        "\n"
        "def view_json():\n"
        "    data = request.json.get('command')\n"
        "    return data\n"
        "\n"
        "def normal_func(x, y):\n"
        "    return x + y\n",
        encoding="utf-8",
    )
    return source_file


def test_extract_args_get_params(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "view_get", "start_line": 3, "end_line": 6},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    params = extract_web_params_from_source(artifact)
    assert params == [
        {"name": "expr", "source": "args"},
        {"name": "template", "source": "args"},
    ]


def test_extract_form_subscript_params(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "view_subscript", "start_line": 8, "end_line": 10},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    params = extract_web_params_from_source(artifact)
    assert params == [{"name": "payload", "source": "form"}]


def test_extract_json_params(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "view_json", "start_line": 12, "end_line": 14},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    params = extract_web_params_from_source(artifact)
    assert params == [{"name": "command", "source": "json"}]


def test_extract_no_web_params(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "normal_func", "start_line": 16, "end_line": 17},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    params = extract_web_params_from_source(artifact)
    assert params == []


def test_extract_nonexistent_function(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "doesnt_exist", "start_line": 100, "end_line": 110},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    params = extract_web_params_from_source(artifact)
    assert params == []


def test_extract_source_file_not_found(tmp_path) -> None:
    artifact = {
        "finding": {"file": "nonexistent.py"},
        "function": {"name": "some_func", "start_line": 1, "end_line": 10},
        "source": {"vhx_repo_root": str(tmp_path)},
    }
    params = extract_web_params_from_source(artifact)
    assert params == []


def test_load_web_params_csv(tmp_path) -> None:
    csv_file = tmp_path / "web_params.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["function_name", "file", "param_name", "source_type"])
        writer.writerow(["view_get", "app.py", "expr", "args"])
        writer.writerow(["view_get", "app.py", "template", "args"])
        writer.writerow(["view_subscript", "app.py", "payload", "form"])

    rows = load_web_params(str(csv_file))
    assert len(rows) == 3
    assert rows[0] == WebParamRow("view_get", "app.py", "expr", "args")
    assert rows[2] == WebParamRow("view_subscript", "app.py", "payload", "form")


def test_merge_web_params_csv_overrides_ast(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "view_get", "start_line": 3, "end_line": 6},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    csv_rows = [
        WebParamRow("view_get", "app.py", "override_param", "args")
    ]
    params = merge_web_params(artifact, csv_rows)
    # Merging should prioritize the CSV records
    assert params == [{"name": "override_param", "source": "args"}]


def test_input_strategy_flask_view_when_web_params(sample_flask_file) -> None:
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "view_get", "start_line": 3, "end_line": 6},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    strategy = get_input_strategy_from_artifact(artifact)
    assert strategy == "flask_view"


def test_signature_builder_existing_direct_params(sample_flask_file) -> None:
    # Function normal_func(x, y) has real parameters so strategy should be direct_params
    artifact = {
        "finding": {"file": "app.py"},
        "function": {"name": "normal_func", "start_line": 16, "end_line": 17},
        "source": {"vhx_repo_root": str(sample_flask_file.parent)},
    }
    strategy = get_input_strategy_from_artifact(artifact)
    assert strategy == "direct_params"


def test_ingest_without_web_params_csv(tmp_path) -> None:
    from oraculum.ingest.runner import run_ingest
    
    # We will verify that running ingest without web_params.csv works normally and just sets empty list/fails gracefully
    vhx_root = tmp_path / "VulnHunterX"
    source = vhx_root / "repos/python/demo/pkg/app.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def view():\n"
        "    return 'hello'\n",
        encoding="utf-8",
    )

    output_root = vhx_root / "output/python/demo"
    output_root.mkdir(parents=True)
    
    # Setup context/functions.csv
    context_dir = output_root / "context"
    context_dir.mkdir()
    (context_dir / "functions.csv").write_text(
        '"name","file","start_line","end_line","scope"\n'
        '"view","pkg/app.py",1,2,"Module pkg.app"\n',
        encoding="utf-8",
    )
    
    # Setup verification_results/summary.json
    ver_dir = output_root / "verification_results"
    ver_dir.mkdir()
    
    summary_data = {
        "timestamp": "2026-05-23T00:00:00",
        "verdicts": [
            {
                "finding": {
                    "rule_id": "py/code-injection",
                    "message": "demo",
                    "file": "pkg/app.py",
                    "start_line": 2,
                    "end_line": 2,
                    "repo_name": "demo",
                    "lang": "python",
                },
                "verdict": "True Positive",
                "reasoning": "demo",
            }
        ]
    }
    (ver_dir / "summary.json").write_text(json.dumps(summary_data), encoding="utf-8")

    res = run_ingest(
        vhx_root=vhx_root,
        repo="demo",
        summary=ver_dir / "summary.json",
        output_dir=tmp_path / "output"
    )
    assert res.ok
    
    # Check that the ingested file has web_params as []
    finding_path = tmp_path / "output/python/demo/verification_results/findings/finding_0_py_code-injection.json"
    assert finding_path.exists()
    payload = json.loads(finding_path.read_text(encoding="utf-8"))
    assert "web_params" in payload
    assert payload["web_params"] == []
