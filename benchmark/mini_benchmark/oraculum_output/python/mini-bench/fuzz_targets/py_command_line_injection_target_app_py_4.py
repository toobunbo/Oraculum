import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/tuonglnc/repo/Oraculum/benchmark/mini_benchmark/vhx_root/repos/python/mini-bench"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from target_app import run_shell


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(".*[&]{2}.*", re.IGNORECASE),

    re.compile(".*[|]{1}.*", re.IGNORECASE),

    re.compile(".*[;]{1}.*", re.IGNORECASE),

    re.compile(".*\\bcat\\b.*", re.IGNORECASE),

    re.compile(".*\\b/etc/passwd\\b.*", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COMMAND-LINE-INJECTION: Command injection detected — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "cmd_input", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : subprocess.run
# target_arg_index : 0
# target_arg_name  : args
# input_strategy   : direct_params
# signature        : def run_shell(cmd_input: str)
# condition        : subprocess.run is called with shell=True and a command containing dangerous patterns like '&&', '|', or ';'
# capture_what     : command string passed to subprocess.run
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Mock the patch target using patch/MagicMock.
# 4. Call target function inside the mock context.
# 5. Compare mock call arguments against _COMPILED_PATTERNS.
# 6. Propagate RuntimeError; swallow other exceptions.
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    cmd_input = fdp.ConsumeUnicodeNoSurrogates(len(data))
    
    with patch("subprocess.run", MagicMock()) as mock_obj:
        try:
            run_shell(cmd_input)
        except Exception:
            pass

        for call in mock_obj.call_args_list:
            captured = ""
            if call.args:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("args", ""))
            
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "cat /etc/passwd",
    "ls -la; cat /etc/passwd",
    "echo test | cat /etc/passwd",
    "echo test && cat /etc/passwd",
    "cat\t/etc/passwd",
    "CAT /ETC/PASSWD",
    "cat /etc/passwd #",
    "cat${IFS}/etc/passwd"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "benchmark/mini_benchmark/oraculum_output/python/mini-bench/fuzz_corpus/py_command_line_injection_target_app_py_4"
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