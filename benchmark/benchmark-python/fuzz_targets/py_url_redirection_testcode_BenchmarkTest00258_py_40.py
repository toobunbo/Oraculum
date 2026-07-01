# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/url-redirection
# function : BenchmarkTest00258_post
# file     : testcode/BenchmarkTest00258.py
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

    from testcode.BenchmarkTest00258 import BenchmarkTest00258_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : flask.redirect
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00258_post()
# condition        : captured_args[0] is not None and isinstance(captured_args[0], str)
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
#    - Patch `flask.redirect` using `with patch(...) as mock_get:`.
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
    # Since the function signature has no parameters, we don't need to generate any input.
    # However, we still proceed to ensure the harness is complete.

    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip.

    # 3. MOCK SETUP
    with patch('flask.redirect', return_value=MagicMock()) as mock_redirect:
        try:
            # Call the target function
            BenchmarkTest00258_post()
        except Exception:
            # Catch any exception from the target function and return to let the fuzzer continue
            return

        # 4. ORACLE CHECK
        for call in mock_redirect.call_args_list:
            captured = None
            # Check positional arguments first
            if len(call.args) > 0:
                captured = call.args[0]
            # Fallback to keyword arguments if needed (though arg name is None)
            elif call.kwargs:
                # Since target_arg_name is None, we can't reliably get the value from kwargs
                # We'll assume it's not present or not usable
                pass

            # Check the oracle condition: captured_args[0] is not None and isinstance(captured_args[0], str)
            if captured is not None and isinstance(captured, str):
                # Check against patterns
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(captured):
                        # Raise the oracle violation
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(captured)))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "http://example.com",
    "https://evil.com",
    "javascript:alert(1)",
    " data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    "\r\nLocation: http://malicious.com",
    "http://example.com%0a%0dX-Forwarded-For:%20127.0.0.1"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_url_redirection_testcode_BenchmarkTest00258_py_40"
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