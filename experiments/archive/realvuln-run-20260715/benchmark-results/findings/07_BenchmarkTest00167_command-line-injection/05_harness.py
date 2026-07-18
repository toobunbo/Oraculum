# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/command-line-injection
# function : BenchmarkTest00167_post
# file     : testcode/BenchmarkTest00167.py
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

    from testcode.BenchmarkTest00167 import BenchmarkTest00167_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : subprocess.run
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00167_post()
# condition        : lambda captured: 'BenchmarkTest00167' in captured
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
#    - Patch `subprocess.run` using `with patch(...) as mock_get:`.
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
    # For flask_request, we simulate a request-like object with form data
    # We'll generate a dictionary to simulate form data
    form_key = fdp.ConsumeUnicodeNoSurrogates(20)
    form_value = fdp.ConsumeUnicodeNoSurrogates(100)
    
    # Create a mock request object
    class MockRequest:
        def __init__(self, form_data):
            self.form = form_data
            self.method = 'POST'
            self.content_type = 'application/x-www-form-urlencoded'
    
    request = MockRequest({form_key: form_value})
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip
    
    # 3. MOCK SETUP
    with patch('subprocess.run', return_value=MagicMock()) as mock_run:
        try:
            # Call the target function
            BenchmarkTest00167_post(request)
        except Exception:
            # Only catch non-Oracle exceptions
            return
        
        # 4. ORACLE CHECK
        # Iterate through all calls to the mocked subprocess.run
        for call in mock_run.call_args_list:
            # Try to get the captured value from args or kwargs
            captured = None
            if call.args:
                captured = call.args[0]  # First argument is typically the command
            elif call.kwargs:
                # If command is passed as a keyword argument
                captured = call.kwargs.get('args', None)
            
            # If we have a captured value, check it against our patterns
            if captured:
                # Convert to string if it's not already
                captured_str = str(captured)
                
                # Check against the condition: 'BenchmarkTest00167' in captured
                if 'BenchmarkTest00167' in captured_str:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str))
                
                # Also check against compiled patterns
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(captured_str):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "BenchmarkTest00167",
    "benchmarktest00167",
    "BENCHMARKTEST00167",
    " BenchmarkTest00167 ",
    "BenchmarkTest00167<script>",
    "B3nchmarkT3st00167",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_command_line_injection_testcode_BenchmarkTest00167_py_53"
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