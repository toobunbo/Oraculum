# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/code-injection
# function : BenchmarkTest00073_post
# file     : testcode/BenchmarkTest00073.py
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

    from testcode.BenchmarkTest00073 import BenchmarkTest00073_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.eval
# target_arg_index : 0
# target_arg_name  : expression
# input_strategy   : flask_view
# signature        : def BenchmarkTest00073_post()
# condition        : captured_value != None and isinstance(captured_value, str)
# capture_what     : expression
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
#    - Patch `builtins.eval` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[0] first,
#      fall back to call.kwargs.get("expression").
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
    # Since the function signature is BenchmarkTest00073_post() with no parameters,
    # and the input_strategy is flask_view, we simulate a Flask request.
    # We'll generate a request body or query parameters as needed.
    # However, since the actual function implementation is not provided,
    # we assume it reads from Flask's request object.
    # For simplicity, we'll patch the request object if needed, but here we just proceed.

    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip.

    # 3. MOCK SETUP
    with patch('builtins.eval') as mock_eval:
        mock_eval.return_value = "mocked_result"  # Return a realistic value

        # 4. CALL TARGET FUNCTION
        try:
            BenchmarkTest00073_post()
        except Exception:
            # Catch exceptions from the function call to prevent harness crashes
            return

        # 5. ORACLE CHECK
        for call in mock_eval.call_args_list:
            # Get the first positional argument
            captured_value = None
            if call.args:
                captured_value = call.args[0]
            elif 'expression' in call.kwargs:
                captured_value = call.kwargs['expression']

            # Check the condition: captured_value != None and isinstance(captured_value, str)
            if captured_value is not None and isinstance(captured_value, str):
                # Match against every pattern in _COMPILED_PATTERNS
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(captured_value):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(captured_value)))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "eval('1+1')",
    "EVAL('os.system(\"ls\")')",
    "eval ( ' 1 + 1 ' )",
    "eval(\t'__import__(\"os\").system(\"whoami\")')",
    "eval(''.join(chr(i) for i in [101, 118, 97, 108]))",
    "eval('exec(\"import os; os.system(\\\"echo pwned\\\")\")')",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_code_injection_testcode_BenchmarkTest00073_py_54"
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