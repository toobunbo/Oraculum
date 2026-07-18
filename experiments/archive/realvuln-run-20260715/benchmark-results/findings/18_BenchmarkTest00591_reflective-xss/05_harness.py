# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/reflective-xss
# function : BenchmarkTest00591_post
# file     : testcode/BenchmarkTest00591.py
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

    from testcode.BenchmarkTest00591 import BenchmarkTest00591_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : flask.Response.__init__
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00591_post()
# condition        : lambda x: '<script>' in x or 'onerror=' in x.lower() or 'javascript:' in x.lower()
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
#    - Patch `flask.Response.__init__` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[0] first,
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
        from werkzeug.test import EnvironBuilder
        from werkzeug.wrappers import Request
    except ImportError:
        return  # Skip if Flask/Werkzeug not available

    # Create a fuzzed request body
    request_body = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    
    # Build a minimal Flask request environment
    builder = EnvironBuilder(method='POST', data=request_body)
    env = builder.get_environ()
    request = Request(env)
    
    # 2. SKIP CONDITION
    # No skip condition specified, proceed
    
    # 3. MOCK SETUP
    with patch('flask.Response.__init__', return_value=None) as mock_response:
        try:
            # Call the target function with the fuzzed request
            BenchmarkTest00591_post(request)
        except Exception:
            # Catch any exception from the target function and return to let fuzzer continue
            return

        # 4. ORACLE CHECK
        for call in mock_response.call_args_list:
            # Extract the first positional argument (index 0)
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]
            elif call.kwargs:
                # Fallback to keyword argument if positional is not available
                captured = call.kwargs.get("None", None)

            if captured is not None:
                # Check against the oracle condition
                if isinstance(captured, str):
                    if '<script>' in captured or 'onerror=' in captured.lower() or 'javascript:' in captured.lower():
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))

    # 5. EXCEPTION HANDLING
    # Handled above with try/except around the target call
    return


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x ONERROR=alert(1)>",
    "jav&#x09;ascript:alert(1)",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_reflective_xss_testcode_BenchmarkTest00591_py_48"
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