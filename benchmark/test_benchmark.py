from __future__ import annotations

import json
import sys
from pathlib import Path
import pytest
from unittest.mock import MagicMock, patch
import subprocess

# We need to import the functions from run_benchmark
# To do that, we add the benchmark directory to sys.path.
project_root = Path(__file__).resolve().parent.parent
benchmark_dir = Path(__file__).resolve().parent
if str(benchmark_dir) not in sys.path:
    sys.path.insert(0, str(benchmark_dir))

from run_benchmark import (
    check_compilation,
    prepare_temp_harness,
    evaluate_target,
    run_pipeline,
)


def test_check_compilation(tmp_path: Path) -> None:
    # Valid Python code
    valid_file = tmp_path / "valid.py"
    valid_file.write_text("def func():\n    pass\n", encoding="utf-8")
    valid, msg = check_compilation(valid_file)
    assert valid is True
    assert msg == ""

    # Invalid Python code
    invalid_file = tmp_path / "invalid.py"
    invalid_file.write_text("def func():\n   pass\n  error syntax", encoding="utf-8")
    valid, msg = check_compilation(invalid_file)
    assert valid is False
    assert "SyntaxError" in msg or "IndentationError" in msg


def test_prepare_temp_harness(tmp_path: Path) -> None:
    original_code = """
import atheris
import re

_COMPILED_PATTERNS = [re.compile("abc")]
_SEED_CORPUS = [
    "seed1",
    "seed2"
]

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # 4. CALL TARGET FUNCTION
    try:
        call_target()
    except Exception:
        return
    # 5. ORACLE CHECK
    for pattern in _COMPILED_PATTERNS:
        if pattern.match(data):
            raise RuntimeError("VIOLATION")

if __name__ == "__main__":
    pass
"""
    harness_path = tmp_path / "harness.py"
    harness_path.write_text(original_code, encoding="utf-8")

    # Test 1: with oracle (only clear seed corpus)
    temp_with = tmp_path / "temp_with.py"
    prepare_temp_harness(harness_path, temp_with, disable_oracle=False)
    content_with = temp_with.read_text(encoding="utf-8")
    assert "_SEED_CORPUS = []" in content_with
    assert "raise RuntimeError(\"VIOLATION\")" in content_with

    # Test 2: no oracle (clear seed corpus AND disable check)
    temp_no = tmp_path / "temp_no.py"
    prepare_temp_harness(harness_path, temp_no, disable_oracle=True)
    content_no = temp_no.read_text(encoding="utf-8")
    assert "_SEED_CORPUS = []" in content_no
    assert "pass" in content_no
    assert "raise RuntimeError(\"VIOLATION\")" not in content_no


def test_prepare_temp_harness_filesystem_state(tmp_path: Path) -> None:
    original_code = """
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        try:
            write_log(filename, content)
        except Exception:
            pass
        # Check for new or modified files
        for root, dirs, files in os.walk(temp_dir):
            raise RuntimeError("VIOLATION")
    finally:
        os.chdir(original_cwd)

_SEED_CORPUS = ["a"]
"""
    harness_path = tmp_path / "harness.py"
    harness_path.write_text(original_code, encoding="utf-8")

    temp_no = tmp_path / "temp_no.py"
    prepare_temp_harness(harness_path, temp_no, disable_oracle=True)
    content_no = temp_no.read_text(encoding="utf-8")
    assert "pass" in content_no
    assert "finally:" in content_no
    assert "os.chdir(original_cwd)" in content_no
    assert "raise RuntimeError" not in content_no


@patch("run_benchmark.run_cmd")
def test_evaluate_target_success(mock_run_cmd, tmp_path: Path) -> None:
    harness = tmp_path / "harness.py"
    harness.write_text("def TestOneInput(data): pass", encoding="utf-8")

    # Mock subprocess runs:
    # 1. Recall run -> exits with 1 and raises RuntimeError
    # 2. Overhead run no-oracle -> exits with 0
    # 3. Overhead run with-oracle -> exits with 0
    mock_run_cmd.side_effect = [
        subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="RuntimeError: ORACULUM_VIOLATION"),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ]

    target = {
        "target_id": "test_target",
        "harness": str(harness.resolve()),
        "corpus": "dummy_corpus",
        "strategy": "recorded_call",
    }

    # Patch time.perf_counter to control overhead calculation
    # First overhead call duration: 1.0s, second: 1.1s -> 10% overhead
    with patch("time.perf_counter", side_effect=[0.0, 1.0, 0.0, 1.1]):
        result = evaluate_target(target, project_root, runs=1000, timeout=5.0)

    assert result["valid"] is True
    assert result["recall"] is True
    assert result["overhead_pct"] == pytest.approx(10.0)
    assert result["error_msg"] == ""


@patch("run_benchmark.run_cmd")
def test_evaluate_target_recall_failed(mock_run_cmd, tmp_path: Path) -> None:
    harness = tmp_path / "harness.py"
    harness.write_text("def TestOneInput(data): pass", encoding="utf-8")

    # Recall run exits with 0 (clean run, no bug detected)
    mock_run_cmd.side_effect = [
        subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
        subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr=""),
    ]

    target = {
        "target_id": "test_target",
        "harness": str(harness.resolve()),
        "corpus": "dummy_corpus",
        "strategy": "recorded_call",
    }

    result = evaluate_target(target, project_root, runs=1000, timeout=5.0)
    assert result["valid"] is True
    assert result["recall"] is False
    assert "failed to trigger violation" in result["error_msg"]


@patch("run_benchmark.run_cmd")
def test_run_pipeline_success(mock_run_cmd) -> None:
    mock_run_cmd.return_value = subprocess.CompletedProcess(args=[], returncode=0, stdout="OK", stderr="")
    success = run_pipeline("demo", "/vhx/root", Path("/out"), force=True)
    assert success is True
    assert mock_run_cmd.call_count == 4
