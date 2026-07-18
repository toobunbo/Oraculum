# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/reflective-xss
# function : BenchmarkTest00256_post
# file     : testcode/BenchmarkTest00256.py
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

    from testcode.BenchmarkTest00256 import BenchmarkTest00256_post


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
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00256_post()
# condition        : lambda captured: '<script>' in captured or '\n' in captured or '\r' in captured
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
    # No explicit input needed for this flask view function with no parameters
    # The request object is handled by the framework, so we proceed directly

    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip

    # 3. MOCK SETUP
    with patch('flask.make_response', return_value=MagicMock()) as mock_make_response:
        try:
            # Call the target function
            BenchmarkTest00256_post()
        except Exception:
            # Catch any exception from the function call and return to let fuzzer continue
            return

        # 4. ORACLE CHECK
        for call in mock_make_response.call_args_list:
            # Get the first argument
            captured = None
            if call.args:
                captured = call.args[0]
            elif call.kwargs:
                # Fallback to kwargs, though arg name is None
                captured = list(call.kwargs.values())[0] if call.kwargs else None

            if captured is not None:
                # Apply the condition: lambda captured: '<script>' in captured or '\n' in captured or '\r' in captured
                if isinstance(captured, str) and ('<script>' in captured or '\n' in captured or '\r' in captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<sCrIpT>alert(1)</sCrIpT>",
    "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e",
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "<script>alert(1)</script>\n",
    "<script>alert(1)</script>\r",
    "<svg onload=alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_reflective_xss_testcode_BenchmarkTest00256_py_48"
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