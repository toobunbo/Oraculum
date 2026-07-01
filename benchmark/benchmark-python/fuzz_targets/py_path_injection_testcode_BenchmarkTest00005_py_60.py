# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/path-injection
# function : BenchmarkTest00005_post
# file     : testcode/BenchmarkTest00005.py
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

    from testcode.BenchmarkTest00005 import BenchmarkTest00005_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : os.path.join
# target_arg_index : 1
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00005_post()
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
#    - Patch `os.path.join` using `with patch(...) as mock_get:`.
#    - Return a realistic MagicMock so the function continues past the patched call.
#
# 4. ORACLE CHECK
#    - After the call, iterate mock_get.call_args_list.
#    - For each call: check call.args[1] first,
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
    # Only one tainted param: "request" at index -1, type flask_request
    # For flask_view strategy, we simulate a POST request with form data
    try:
        form_data_count = fdp.ConsumeIntInRange(0, 10)
        form_data = {}
        for _ in range(form_data_count):
            key = fdp.ConsumeUnicodeNoSurrogates(32)
            value = fdp.ConsumeUnicodeNoSurrogates(100)
            form_data[key] = value
            
        # Create a mock request object
        request = MagicMock()
        request.method = "POST"
        request.form = form_data
        request.args = {}
        request.cookies = {}
        request.headers = {}
        
    except Exception:
        return  # Return early for malformed input
    
    # 2. SKIP CONDITION
    # skip_hint is False, so no skip condition to apply
    
    # 3. MOCK SETUP
    with patch('os.path.join', return_value='/safe/path') as mock_join:
        try:
            # Create an instance of the test class
            test_instance = BenchmarkTest00005_post()
            
            # Call the target function with the generated request
            test_instance.post(request)
            
        except Exception:
            # Only catch non-oracle exceptions around the target function call
            return
            
        # 4. ORACLE CHECK
        # Iterate through all recorded calls to os.path.join
        for call in mock_join.call_args_list:
            # Extract the second argument (index 1) as per target_arg_index
            captured = None
            if len(call.args) > 1:
                captured = call.args[1]
            elif "None" in call.kwargs:  # Fallback to kwargs if needed
                captured = call.kwargs.get("None")
                
            # Check if we have a captured value to inspect
            if captured is not None:
                # Match against every pattern in _COMPILED_PATTERNS
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(str(captured)):
                        # On match, raise RuntimeError with the captured value
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "../etc/passwd",
    "..\\system32\\drivers\\etc\\hosts",
    "/../../../../etc/shadow",
    "C:\\Windows\\System32\\config\\SAM",
    "../../../boot.ini",
    "/proc/self/environ",
    "file://localhost/etc/passwd",
    "%2e%2e%2fetc%2fpasswd",
    "\\??\\C:\\Windows\\System32\\drivers\\etc\\hosts",
    "/dev/null; rm -rf /",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_path_injection_testcode_BenchmarkTest00005_py_60"
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