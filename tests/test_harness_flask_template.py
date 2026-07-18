from __future__ import annotations

import json
from pathlib import Path
import pytest

from oraculum.harness.template_builder import build_skeleton


def test_flask_view_has_request_context(tmp_path: Path) -> None:
    # OWASP-Benchmark-style source: handler nested in def init(app).
    src = tmp_path / "vulnerable_app.py"
    src.write_text(
        "from flask import request\n"
        "def init(app):\n"
        "    @app.route('/v')\n"
        "    def view_get():\n"
        "        expr = request.form.get('expr')\n"
        "        return eval(expr)\n",
        encoding="utf-8",
    )

    artifact = {
        "id": "1",
        "rule_slug": "py_code_injection",
        "source": {
            "vhx_repo_root": str(tmp_path),
        },
        "finding": {
            "rule_id": "py/code-injection",
            "message": "code injection",
            "file": "vulnerable_app.py",
            "start_line": 4,
            "end_line": 6,
        },
        "verification": {
            "verdict": "True Positive",
            "reasoning": "eval",
        },
        "function": {
            "name": "view_get",
            "start_line": 3,
            "end_line": 6,
        },
    }

    oracle_spec_flask = {
        "monitor": {
            "strategy": "recorded_call",
            "target": "builtins.eval",
            "patch_target": "builtins.eval",
            "additional_imports": [],
        },
        "oracle_check": {
            "condition_description": "code contains exploit",
            "trigger_patterns": [".*"],
            "raise_type": "RuntimeError",
            "raise_message_template": "exploit detected: captured={captured}",
        },
        "fuzz_guidance": {
            "seed_corpus": [],
            "skip_condition": "False",
        },
        "_meta": {
            "target_id": "py_code_injection_vulnerable_app_py_4",
            "finding_id": "1",
            "rule_id": "py/code-injection",
            "rule_slug": "py_code_injection",
            "file": "vulnerable_app.py",
            "function": "view_get",
            "input_strategy": "flask_view",
            "function_signature": "def view_get()",
            "tainted_params": [
                {"name": "expr", "index": -1, "type": "str"}
            ],
            "source_finding_artifact": "dummy_path",
        },
    }

    skeleton = build_skeleton(
        artifact=artifact,
        spec=oracle_spec_flask,
        repo_root=str(tmp_path),
        corpus_dir="/tmp/dummy/corpus",
    )

    # 1. Deterministic flask path: module import + init(app) + view_functions.
    assert "import vulnerable_app as _target_mod" in skeleton
    assert "_target_mod.init(_app)" in skeleton
    assert '_app.view_functions["view_get"]' in skeleton

    # 2. No LLM fill markers — the harness is complete and deterministic.
    assert "[FILL HERE]" not in skeleton

    # 3. Detected form input source drives the request context.
    assert "test_request_context(" in skeleton

    # 4. Sink patch target + oracle contract present.
    assert '_PATCH_TARGET = "builtins.eval"' in skeleton
    assert "with patch(_PATCH_TARGET)" in skeleton
    assert "exploit detected" in skeleton

    # 5. Compiles cleanly.
    assert compile(skeleton, "<string>", "exec") is not None


def test_input_source_detection(tmp_path: Path) -> None:
    from oraculum.harness.input_source import detect_input_source

    src = tmp_path / "m.py"
    src.write_text(
        "from flask import request\n"
        "def init(app):\n"
        "    @app.route('/c', methods=['POST'])\n"
        "    def h_post():\n"
        "        v = request.cookies.get('sid')\n"
        "        open(v)\n",
        encoding="utf-8",
    )
    res = detect_input_source(src, "h_post")
    assert res.kind == "cookie"
    assert res.key == "sid"


def test_direct_params_no_flask_code() -> None:
    artifact = {
        "id": "1",
        "rule_slug": "py_code_injection",
        "source": {
            "vhx_repo_root": "/tmp/dummy",
        },
        "finding": {
            "rule_id": "py/code-injection",
            "message": "code injection",
            "file": "utils.py",
            "start_line": 5,
            "end_line": 6,
        },
        "verification": {
            "verdict": "True Positive",
            "reasoning": "untrusted input reaches eval",
        },
        "function": {
            "name": "safe_eval",
            "start_line": 4,
            "end_line": 7,
        },
    }

    oracle_spec_direct = {
        "monitor": {
            "strategy": "recorded_call",
            "patch_target": "builtins.eval",
            "target_arg_index": 0,
            "target_arg_name": None,
            "capture_what": "code passed to eval",
            "additional_imports": [],
        },
        "oracle_check": {
            "condition_description": "code contains exploit",
            "trigger_patterns": [".*"],
            "raise_type": "RuntimeError",
            "raise_message_template": "exploit detected",
        },
        "fuzz_guidance": {
            "seed_corpus": [],
            "skip_condition": "False",
        },
        "_meta": {
            "target_id": "py_code_injection_utils_py_5",
            "finding_id": "1",
            "rule_id": "py/code-injection",
            "rule_slug": "py_code_injection",
            "file": "utils.py",
            "function": "safe_eval",
            "input_strategy": "direct_params",
            "function_signature": "def safe_eval(expr: str)",
            "tainted_params": [
                {"name": "expr", "index": 0, "type": "str"}
            ],
            "source_finding_artifact": "dummy_path",
        },
    }

    skeleton = build_skeleton(
        artifact=artifact,
        spec=oracle_spec_direct,
        repo_root="/tmp/dummy",
        corpus_dir="/tmp/dummy/corpus",
    )

    # 1. Verify app import is NOT added
    assert "import app" not in skeleton

    # 2. Verify request context block is NOT rendered
    assert "app.test_request_context" not in skeleton
    assert "query_params" not in skeleton

    # 3. Ensure the code compiles cleanly
    compiled = compile(skeleton, "<string>", "exec")
    assert compiled is not None
