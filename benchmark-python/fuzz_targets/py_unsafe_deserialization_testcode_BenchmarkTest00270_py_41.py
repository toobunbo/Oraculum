# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/unsafe-deserialization
# function : BenchmarkTest00270_post
# file     : testcode/BenchmarkTest00270.py
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

    from testcode.BenchmarkTest00270 import BenchmarkTest00270_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : yaml.yaml.load
# target_arg_index : 0
# target_arg_name  : stream
# input_strategy   : flask_view
# signature        : def BenchmarkTest00270_post()
# condition        : Verify that yaml.load was called with a string argument containing '_SafeStuff', indicating user-controlled input reached the unsafe deserialization sink
# capture_what     : stream
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
#    - Patch `yaml.yaml.load` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[0] first,
#      fall back to call.kwargs.get("stream").
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
    # Only one tainted param: "request" of type flask_request
    # For flask_view strategy, we simulate a POST request with form data
    # We'll create a minimal WSGI environment with a body containing our fuzzed data
    try:
        # Consume a string to use as the request body
        body_str = fdp.ConsumeUnicodeNoSurrogates(1024)
        # Skip if body is empty or malformed for our purposes
        if not body_str:
            return

        # Create a mock WSGI environment
        from io import BytesIO
        from werkzeug.datastructures import ImmutableMultiDict

        wsgi_input = BytesIO(body_str.encode('utf-8'))
        environ = {
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'wsgi.input': wsgi_input,
            'CONTENT_LENGTH': str(len(body_str)),
        }

        # Create a mock request object
        from werkzeug.test import EnvironBuilder
        builder = EnvironBuilder(
            path='/',
            method='POST',
            data=body_str,
            environ_base=environ
        )
        request = builder.get_request()

        # 2. SKIP CONDITION
        # skip_hint is False, so we don't skip

        # 3. MOCK SETUP
        with patch('yaml yaml.load', side_effect=lambda s, **kwargs: {"parsed": "data"}) as mock_get:
            # 4. CALL TARGET FUNCTION
            try:
                BenchmarkTest00270_post(request)
            except Exception:
                # Catch exceptions from the target function to prevent harness crashes
                return

            # 5. ORACLE CHECK
            for call in mock_get.call_args_list:
                # Get the first positional argument (index 0) or keyword argument 'stream'
                captured = None
                if call.args:
                    captured = call.args[0]
                elif 'stream' in call.kwargs:
                    captured = call.kwargs['stream']

                # Check if captured value matches any pattern
                if captured is not None:
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(str(captured)):
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))

    except RuntimeError:
        # Re-raise oracle violations
        raise
    except Exception:
        # Ignore other exceptions to prevent harness crashes
        return


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "!!python/object/apply:os.getpid []",
    "!!python/object/apply:os.system ['echo vulnerable']",
    "!!python/object/apply:subprocess.Popen [['ls']]",
    "!!python/object/new:tuple [!!python/object/apply:map [!!python/name:eval , 'import os; os.system(\"id\")']]",
    "!!python/object/apply:__import__ [os] !!python/object/apply:getattr [os, system] !!python/object/apply:system [id]",
    "!!python/object/apply:exec ['import os; os.system(\"id\")']",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_unsafe_deserialization_testcode_BenchmarkTest00270_py_41"
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