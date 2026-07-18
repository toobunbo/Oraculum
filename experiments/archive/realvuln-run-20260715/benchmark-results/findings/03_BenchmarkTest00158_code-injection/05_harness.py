# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/code-injection
# function : BenchmarkTest00158_post
# file     : testcode/BenchmarkTest00158.py
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

    from testcode.BenchmarkTest00158 import BenchmarkTest00158_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : builtins.eval
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00158_post()
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
#    - Patch `builtins.eval` using `with patch(...) as mock_get:`.
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
    # For flask_view strategy, we need to simulate a Flask request.
    # Since the function signature is BenchmarkTest00158_post(), it likely expects a request object.
    # We'll create a mock request with fuzzed data.
    
    # Consume a string to use as request data
    request_data = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 2048))
    
    # Early return for empty data
    if not request_data:
        return
    
    # 2. SKIP CONDITION
    # skip_hint is False, so no skip condition to apply
    
    # 3. MOCK SETUP
    with patch('builtins.eval') as mock_eval:
        # Set up the mock to return a realistic value
        mock_eval.return_value = None
        
        try:
            # Create a mock request object
            from unittest.mock import Mock
            mock_request = Mock()
            mock_request.get_data.return_value = request_data.encode('utf-8')
            mock_request.form = {}
            mock_request.args = {}
            
            # If we have key-value pairs, add them to form
            if '=' in request_data:
                try:
                    key, value = request_data.split('=', 1)
                    mock_request.form[key] = value
                except:
                    pass
            
            # Patch Flask's request object if needed
            with patch('testcode.BenchmarkTest00158.request', mock_request):
                # Call the target function
                BenchmarkTest00158_post()
        except Exception:
            # Only catch non-oracle exceptions around the target call
            return
    
    # 4. ORACLE CHECK
    # Check if eval was called with any arguments
    for call in mock_eval.call_args_list:
        captured = None
        
        # Try to get the first positional argument
        if call.args:
            captured = call.args[0]
        # Fallback to keyword arguments if needed
        elif call.kwargs:
            # Since target_arg_name is None, we don't know the exact kwarg name
            # We'll check all keyword arguments
            for kwarg_value in call.kwargs.values():
                captured = kwarg_value
                break
        
        # Check the oracle condition: captured_args[0] is not None and isinstance(captured_args[0], str)
        if captured is not None and isinstance(captured, str):
            # Match against patterns
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(captured)))

# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "eval(__import__('os').system('ls'))",
    "EVAL( __import__( 'os' ). system ( 'ls' ) )",
    "\u0065\u0076\u0061\u006c(...)",  # Unicode for eval(...)
    "eval ( chr(101)+chr(118)+chr(97)+chr(108) )",  # Obfuscated eval
    "eval(\t\n\r__import__('subprocess').getoutput('id'))",
    "globals().__getitem__('__builtins__').eval('print(1)')"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_code_injection_testcode_BenchmarkTest00158_py_56"
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