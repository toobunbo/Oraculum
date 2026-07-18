# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/code-injection
# function : BenchmarkTest00159_post
# file     : testcode/BenchmarkTest00159.py
# ================================================================
import atheris
import sys
import re
import os


from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/tuonglnc/repo/VulnHunterX/repos/python/benchmark-python"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from testcode.BenchmarkTest00159 import BenchmarkTest00159_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.exec
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00159_post()
# condition        : Captured exec argument is a non-empty string, indicating potential code injection
# capture_what     : captured value
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===
# 1. INPUT GENERATION
#    - Generate inputs for tainted params using FuzzedDataProvider.
#    - For MULTIPLE params: split the buffer proportionally by param count.
#      For str/bytes params divide remaining bytes evenly; consume the last
#      str/bytes param with remaining bytes. Fixed-size types (int, float,
#      bool) consume their natural byte width first.
#      FORBIDDEN: Do NOT use ConsumeIntInRange() to index a strategy or branch.
#    - DO NOT embed a seed list inside TestOneInput or use ConsumeBool() to
#      select from a hardcoded list — seeds are managed externally in _SEED_CORPUS.
#
# 2. SKIP CONDITION
#    - Apply skip_hint early, return immediately if not met.
#
# 3. MOCK SETUP
#    - Patch `builtins.exec` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[None] first,
#      fall back to call.kwargs.get("None").
#    - Match against every pattern in _COMPILED_PATTERNS.
#    - On match → raise RuntimeError(_RAISE_MESSAGE)
#
# 5. EXCEPTION HANDLING
#    - except RuntimeError: raise   → never swallow oracle signals
#    - except Exception:    return  → only around the target function call
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # 1. INPUT GENERATION
    # Generate a mock Flask request object with fuzzed data
    try:
        request_data = {
            "form": {
                "input": fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 1024))
            }
        }
    except Exception:
        return  # Invalid or malformed input, skip

    # 2. SKIP CONDITION (none specified, so always proceed)

    # 3. MOCK SETUP
    with patch("builtins.exec", return_value=None) as mock_exec:
        try:
            # Call the target function with the generated request
            BenchmarkTest00159_post(request_data)
        except Exception:
            return  # Catch exceptions from the target function to prevent harness crashes

        # 4. ORACLE CHECK
        for call in mock_exec.call_args_list:
            # Extract the captured argument
            captured = None
            if call.args:
                captured = call.args[0] if len(call.args) > 0 else None
            if captured is None and call.kwargs:
                captured = call.kwargs.get("None", None)

            # Check if captured is a non-empty string
            if isinstance(captured, str) and captured:
                # Match against patterns
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(captured):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(captured)))

    # 5. EXCEPTION HANDLING
    # RuntimeError is allowed to propagate (oracle signal)
    # Other exceptions are suppressed to keep fuzzing


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "import os; os.system('ls')",
    "exec('print(123)')",
    "__import__('os').system('whoami')",
    "globals()['__builtins__'].exec('print(456)')",
    "getattr(__import__('builtins'), 'exec')('print(789)')",
    "vars(__builtins__)['exec']('print(000)')"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_code_injection_testcode_BenchmarkTest00159_py_45"
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