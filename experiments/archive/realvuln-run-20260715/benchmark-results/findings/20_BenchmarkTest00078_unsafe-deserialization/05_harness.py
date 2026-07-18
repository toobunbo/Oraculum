# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/unsafe-deserialization
# function : BenchmarkTest00078_post
# file     : testcode/BenchmarkTest00078.py
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

    from testcode.BenchmarkTest00078 import BenchmarkTest00078_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pickle.loads
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00078_post()
# condition        : Any tainted input reaching pickle.loads is a violation
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
#    - Patch `pickle.loads` using `with patch(...) as mock_get:`.
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
    # Only one tainted param: "request" of type flask_request
    # For flask_request, we simulate a POST request with form data
    # We'll create a mock Flask request object with a 'data' field
    request_data = fdp.ConsumeBytes(fdp.remaining_bytes())
    
    # Early return for empty or malformed inputs
    if not request_data:
        return

    # Create a mock Flask request object
    class MockRequest:
        def __init__(self, data):
            self.data = data
            self.method = 'POST'
            self.content_type = 'application/octet-stream'
            self.environ = {}
    
    mock_request = MockRequest(request_data)

    # 2. SKIP CONDITION
    # No skip hint specified, so we proceed

    # 3. MOCK SETUP
    with patch('pickle.loads', return_value=MagicMock()) as mock_pickle:
        try:
            # Call the target function with the mock request
            BenchmarkTest00078_post.__globals__['request'] = mock_request
            BenchmarkTest00078_post()
        except Exception:
            # Catch any exceptions from the function call and return
            # This prevents harness crashes from non-oracle issues
            return

        # 4. ORACLE CHECK
        # Check if pickle.loads was called
        for call in mock_pickle.call_args_list:
            # Get the captured argument (first positional argument)
            captured = None
            if call.args:
                captured = call.args[0]
            elif "None" in call.kwargs:  # Using "None" as string since target_arg_name is None
                captured = call.kwargs.get("None")
            
            if captured is not None:
                # Check against all patterns
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(str(captured)):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))

    # 5. EXCEPTION HANDLING
    # RuntimeError is allowed to propagate (handled by Atheris)
    # All other exceptions are caught by the outer try/except in the function call


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "cos\nsystem\n(S'echo ORACLE_VIOLATION'\ntR.",
    "cos\nsystem\n(S'ls -la'\ntR.",
    "cos\nsystem\n(S'cat /etc/passwd'\ntR.",
    "cos\nsystem\n(S'id'\ntR.",
    "cos\nsystem\n(S'whoami'\ntR.",
    "cos\nsystem\n(S'uname -a'\ntR.",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_unsafe_deserialization_testcode_BenchmarkTest00078_py_53"
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