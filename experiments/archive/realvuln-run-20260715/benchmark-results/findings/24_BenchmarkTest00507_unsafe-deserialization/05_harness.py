# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/unsafe-deserialization
# function : BenchmarkTest00507_post
# file     : testcode/BenchmarkTest00507.py
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

    from testcode.BenchmarkTest00507 import BenchmarkTest00507_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pickle.pickle.loads
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00507_post()
# condition        : lambda arg: isinstance(arg, bytes) and (b'__reduce__' in arg or b'__getattr__' in arg or b'__setattr__' in arg or b'__delattr__' in arg or b'__getstate__' in arg or b'__setstate__' in arg or b'__reduce_ex__' in arg or b'exec' in arg or b'eval' in arg or b'compile' in arg or b'import' in arg or b'open' in arg or b'os' in arg or b'subprocess' in arg or b'system' in arg or b'popen' in arg or b'pickle' in arg or b'loads' in arg or b'load' in arg)
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
#    - Patch `pickle.pickle.loads` using `with patch(...) as mock_get:`.
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
    # Only one tainted param: "request" of type flask_request
    # For flask_request, we simulate it by creating a dict-like object with .form, .args, etc.
    # Since we don't have access to the actual Flask request object, we'll pass a mock or dict
    # But since the function signature is BenchmarkTest00507_post(), it likely accesses request.form or similar
    # We'll simulate a request-like object with form data

    # Generate a random string for form data
    form_data_bytes = fdp.ConsumeBytes(fdp.remaining_bytes // 2)
    form_data_str = form_data_bytes.decode('utf-8', errors='ignore')

    # Create a mock request object
    class MockRequest:
        def __init__(self, form_data):
            self.form = {'data': form_data}
            self.args = {}
            self.cookies = {}
            self.headers = {}

    mock_request = MockRequest(form_data_str)

    # Patch flask.request to return our mock
    with patch('flask.request', mock_request):
        # 2. SKIP CONDITION
        # skip_hint is False, so no skip

        # 3. MOCK SETUP
        with patch('pickle.pickle.loads', return_value=MagicMock()) as mock_get:
            try:
                # Call the target function
                BenchmarkTest00507_post()
            except Exception:
                # Catch any exception from the function and return to let fuzzer continue
                return

            # 4. ORACLE CHECK
            for call in mock_get.call_args_list:
                # Get the first positional argument
                captured = None
                if call.args:
                    captured = call.args[0]
                elif call.kwargs:
                    # Fallback to kwargs, though arg name is None
                    captured = call.kwargs.get(None)

                if captured is not None:
                    # Check the oracle condition
                    if isinstance(captured, bytes) and (
                        b'__reduce__' in captured or
                        b'__getattr__' in captured or
                        b'__setattr__' in captured or
                        b'__delattr__' in captured or
                        b'__getstate__' in captured or
                        b'__setstate__' in captured or
                        b'__reduce_ex__' in captured or
                        b'exec' in captured or
                        b'eval' in captured or
                        b'compile' in captured or
                        b'import' in captured or
                        b'open' in captured or
                        b'os' in captured or
                        b'subprocess' in captured or
                        b'system' in captured or
                        b'popen' in captured or
                        b'pickle' in captured or
                        b'loads' in captured or
                        b'load' in captured
                    ):
                        # Match against patterns
                        matched = False
                        for pattern in _COMPILED_PATTERNS:
                            if pattern.match(str(captured)):
                                matched = True
                                break
                        if matched:
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULc3lzdGVtKCJ3aG9hbWkiqQ==",
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULX19yZWR1Y2VfX6k=",
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULZXhlYygibHMgLWxhIik=",
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULb3Muc3lzdGVtKCJpZCIp",
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULcGlja2xlLmxvYWRzKCJ0ZXN0Iik=",
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULX19nZXRzdGF0ZV9f",
    "gASVHgAAAAAAAAB9lCiMBGRhdGFxAVULX19zZXRzdGF0ZV9f",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_unsafe_deserialization_testcode_BenchmarkTest00507_py_55"
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