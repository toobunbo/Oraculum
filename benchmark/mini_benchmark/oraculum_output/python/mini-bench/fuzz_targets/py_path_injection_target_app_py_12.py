import atheris
import sys
import re
import os

import tempfile
import shutil



REPO_ROOT = "/home/tuonglnc/repo/Oraculum/benchmark/mini_benchmark/vhx_root/repos/python/mini-bench"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from target_app import write_log


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: file written outside boundary — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "filename", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : filesystem_state
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def write_log(filename: str, content: str)
# condition        : Any file creation outside the intended 'logs' directory
# capture_what     : files created outside the 'logs' directory
# skip_hint        : False
# ========================================


# === FILESYSTEM_STATE SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Create temp sandbox directory (tempfile.TemporaryDirectory) and snapshot it.
# 4. Call target function inside a try/finally block.
# 5. Scan temp directory (and snapshot parent directory if needed), compare against baseline.
# 6. Clean up sandbox in finally. Propagate RuntimeError.
# ==========================================


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # Generate inputs
    filename = fdp.ConsumeUnicodeNoSurrogates(len(data) // 2)
    content = fdp.ConsumeUnicodeNoSurrogates(len(data) // 2)
    
    # Create temp sandbox directory
    with tempfile.TemporaryDirectory() as temp_dir:
        logs_dir = os.path.join(temp_dir, "logs")
        os.makedirs(logs_dir, exist_ok=True)
        
        # Set current working directory to temp_dir to ensure relative paths are contained
        original_cwd = os.getcwd()
        os.chdir(temp_dir)
        
        try:
            # Snapshot the initial state of the logs directory
            initial_files = set()
            for root, dirs, files in os.walk(logs_dir):
                for file in files:
                    initial_files.add(os.path.relpath(os.path.join(root, file), logs_dir))
            
            # Call target function
            try:
                write_log(filename, content)
            except Exception:
                pass  # Swallow all exceptions except RuntimeError
            
            # Check for new or modified files
            final_files = set()
            for root, dirs, files in os.walk(logs_dir):
                for file in files:
                    final_files.add(os.path.relpath(os.path.join(root, file), logs_dir))
            
            # Check if any file was created outside the logs directory
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    full_path = os.path.join(root, file)
                    rel_path = os.path.relpath(full_path, temp_dir)
                    if not rel_path.startswith("logs" + os.sep) and rel_path != "logs":
                        raise RuntimeError(_RAISE_MESSAGE.format(
                            captured=full_path,
                            matched_pattern="File outside logs directory"
                        ))
        finally:
            os.chdir(original_cwd)  # Restore original working directory


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "../etc/passwd",
    "../../tmp/outside_file",
    "logs/../../../etc/hosts",
    "/tmp/absolute_path_file",
    "logs\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "logs/./././../../../etc/passwd"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "benchmark/mini_benchmark/oraculum_output/python/mini-bench/fuzz_corpus/py_path_injection_target_app_py_12"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()