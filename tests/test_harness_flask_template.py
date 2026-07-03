from __future__ import annotations

import json
from pathlib import Path
import pytest

from oraculum.harness.template_builder import build_skeleton


def test_flask_view_has_request_context() -> None:
    artifact = {
        "id": "1",
        "rule_slug": "py_code_injection",
        "source": {
            "vhx_repo_root": "/tmp/dummy",
        },
        "finding": {
            "rule_id": "py/code-injection",
            "message": "code injection",
            "file": "vulnerable_app.py",
            "start_line": 10,
            "end_line": 15,
        },
        "verification": {
            "verdict": "True Positive",
            "reasoning": "untrusted input reaches eval",
        },
        "function": {
            "name": "view_get",
            "start_line": 9,
            "end_line": 16,
        },
    }

    oracle_spec_flask = {
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
            "target_id": "py_code_injection_vulnerable_app_py_10",
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
        repo_root="/tmp/dummy",
        corpus_dir="/tmp/dummy/corpus",
    )

    # 1. Verify app import is added
    assert "from vulnerable_app import app, view_get" in skeleton or "from vulnerable_app import app" in skeleton

    # 2. Verify request context block is rendered
    assert "with app.test_request_context" in skeleton
    assert 'query_string=query_params' in skeleton
    assert 'param_expr = fdp.ConsumeBytes(1024).decode(\'utf-8\', errors=\'ignore\')' in skeleton
    assert '"expr": param_expr' in skeleton

    # 3. Ensure the code compiles cleanly
    compiled = compile(skeleton, "<string>", "exec")
    assert compiled is not None


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
