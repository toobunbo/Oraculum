# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/reflective-xss
# function : BenchmarkTest01083_post
# file     : testcode/BenchmarkTest01083.py
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

    from testcode.BenchmarkTest01083 import BenchmarkTest01083_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : flask.make_response
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest01083_post()
# condition        : oracle condition
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
#    - Patch `flask.make_response` using `with patch(...) as mock_get:`.
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
    # Since the function signature is BenchmarkTest01083_post() with no parameters,
    # and the tainted param is flask_request, we simulate a request object.
    # However, the actual function likely accesses request.form or request.args.
    # We will pass no arguments to the function as per its signature.
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip.
    
    # 3. MOCK SETUP
    with patch('flask.make_response', return_value=MagicMock()) as mock_make_response:
        try:
            # 4. CALL TARGET FUNCTION
            BenchmarkTest01083_post()
        except Exception:
            # Catch any exception from the function and return to let fuzzer continue
            return

        # 5. ORACLE CHECK
        for call in mock_make_response.call_args_list:
            # Since target_arg_index and target_arg_name are None,
            # we check all args and kwargs for a match.
            captured = None
            # Check positional args
            if call.args:
                captured = call.args[0] if len(call.args) > 0 else None
            # Fallback to keyword args
            if captured is None and call.kwargs:
                # Since target_arg_name is None, we check any kwarg
                if call.kwargs:
                    # Get the first kwarg value
                    captured = next(iter(call.kwargs.values()))
            
            if captured is not None:
                # Ensure captured is a string for pattern matching
                if not isinstance(captured, str):
                    captured_str = str(captured)
                else:
                    captured_str = captured
                
                # Match against every pattern
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured_str):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str))
    
    # If we reach here, no violation was detected
    return


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<script>alert('XSS')</script>",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_reflective_xss_testcode_BenchmarkTest01083_py_45"
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