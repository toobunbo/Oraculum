from __future__ import annotations

from pathlib import Path
import pytest

PROMPTS_DIR = Path(__file__).parent.parent / "config" / "prompts"

def test_recorded_call_prompt_has_consume_bytes_rule():
    prompt_path = PROMPTS_DIR / "harness_system_recorded_call.txt"
    content = prompt_path.read_text(encoding="utf-8")
    assert "ConsumeBytes" in content
    assert "decode('utf-8', errors='ignore')" in content

def test_recorded_call_prompt_warns_no_surrogate():
    prompt_path = PROMPTS_DIR / "harness_system_recorded_call.txt"
    content = prompt_path.read_text(encoding="utf-8")
    assert "Do NOT use ConsumeUnicodeNoSurrogates" in content

def test_return_value_prompt_has_consume_bytes_rule():
    prompt_path = PROMPTS_DIR / "harness_system_return_value.txt"
    content = prompt_path.read_text(encoding="utf-8")
    assert "ConsumeBytes" in content
    assert "decode('utf-8', errors='ignore')" in content

def test_filesystem_state_prompt_has_consume_bytes_rule():
    prompt_path = PROMPTS_DIR / "harness_system_filesystem_state.txt"
    content = prompt_path.read_text(encoding="utf-8")
    assert "ConsumeBytes" in content
    assert "decode('utf-8', errors='ignore')" in content

def test_template_skeleton_has_consume_bytes_note():
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
            "strategy": "return_value",
            "patch_target": None,
            "target_arg_index": None,
            "target_arg_name": None,
            "capture_what": "return value",
            "additional_imports": [],
        },
        "oracle_check": {
            "condition_description": "sanitized output",
            "trigger_patterns": [],
            "raise_type": "RuntimeError",
            "raise_message_template": "error",
        },
        "fuzz_guidance": {
            "seed_corpus": [],
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
            "function_signature": "def write_data(data: str)",
            "tainted_params": [
                {"name": "data", "index": 0, "type": "str"},
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
    
    assert "NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')" in skeleton

def test_consume_bytes_preserves_seed():
    try:
        import atheris
    except ImportError:
        pytest.skip("Atheris not installed")

    seed_bytes = b"__import__('os').system('id')"
    fdp = atheris.FuzzedDataProvider(seed_bytes)
    decoded = fdp.ConsumeBytes(len(seed_bytes)).decode('utf-8', errors='ignore')
    assert decoded == "__import__('os').system('id')"
