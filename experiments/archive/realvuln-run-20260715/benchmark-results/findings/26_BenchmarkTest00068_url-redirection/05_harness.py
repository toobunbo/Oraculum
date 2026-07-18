# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/url-redirection
# function : BenchmarkTest00068_post
# file     : testcode/BenchmarkTest00068.py
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

    from testcode.BenchmarkTest00068 import BenchmarkTest00068_post


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
# target_arg_name  : location
# input_strategy   : flask_view
# signature        : def BenchmarkTest00068_post()
# condition        : captured_args[0] contains taint from request.cookies.get('BenchmarkTest00068')
# capture_what     : location
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
#      fall back to call.kwargs.get("location").
#    - Match against every pattern in _COMPILED_PATTERNS.
#    - On match → raise RuntimeError(_RAISE_MESSAGE)
#
# 5. EXCEPTION HANDLING
#    - except RuntimeError: raise   → never swallow oracle signals
#    - except Exception:    return  → only around the target function call
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # [FILL HERE — follow the skeleton above]

    # 1. INPUT GENERATION
    # Since the function signature is BenchmarkTest00068_post() with no parameters,
    # and the taint comes from request.cookies.get('BenchmarkTest00068'),
    # we don't need to generate any specific input from fdp for this case.
    # The taint is handled internally by the application logic.
    # However, to ensure the function is called with a proper context,
    # we proceed without additional input generation.

    # 2. SKIP CONDITION
    # There is no skip hint provided, so we do not apply any skip condition.

    # 3. MOCK SETUP
    with patch('flask.redirect') as mock_redirect:
        # Return a MagicMock to allow the function to continue past the patched call
        mock_redirect.return_value = MagicMock()

        try:
            # Call the target function
            BenchmarkTest00068_post()
        except Exception:
            # Catch any exception from the function call and return to avoid crashing the fuzzer
            return

        # 4. ORACLE CHECK
        # Iterate through all calls to the mocked function
        for call in mock_redirect.call_args_list:
            # Extract the 'location' argument
            captured = None
            if call.args:
                # The first positional argument is 'location'
                captured = call.args[0]
            elif 'location' in call.kwargs:
                captured = call.kwargs['location']
            else:
                # If 'location' is not found, skip this call
                continue

            # Check if the captured value matches any of the compiled patterns
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(str(captured)):
                    # If a match is found, raise the RuntimeError with the message
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))

    # If no match was found, the function ends normally


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "http://example.com",
    "https://evil.com",
    " javascript:alert(1)",
    " data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
    " http://localhost:8080/callback",
    " https://attacker.com/redirect",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_url_redirection_testcode_BenchmarkTest00068_py_49"
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