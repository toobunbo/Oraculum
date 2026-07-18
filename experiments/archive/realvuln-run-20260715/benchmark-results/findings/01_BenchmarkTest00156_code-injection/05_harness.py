# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/code-injection
# function : BenchmarkTest00156_post
# file     : testcode/BenchmarkTest00156.py
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

    from testcode.BenchmarkTest00156 import BenchmarkTest00156_post


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
# signature        : def BenchmarkTest00156_post()
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
    # Only one tainted param: "request" of type flask_request
    # For flask_request, we need to simulate a request object.
    # Since we're not actually running Flask, we'll pass a dictionary
    # that mimics the structure of a Flask request.
    # However, since the function signature is BenchmarkTest00156_post(),
    # it likely accesses request.form or request.args.
    # We'll generate a dictionary for form data.
    # Let's assume it accesses request.form.get('query')
    query_value = fdp.ConsumeUnicodeNoSurrogates(100)
    request_data = {
        'form': {
            'query': query_value
        }
    }
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip
    
    # 3. MOCK SETUP
    with patch('builtins.eval') as mock_eval:
        # Return a realistic MagicMock
        mock_eval.return_value = "mocked_result"
        
        # 4. CALL TARGET FUNCTION
        try:
            # We need to pass the request-like object to the function
            # Since the function is a method of a class, we might need to instantiate it
            # But since we don't have the class, and it's likely a Flask view,
            # we'll assume it accesses a global 'request' object.
            # Let's patch 'flask.request' to return our request_data
            with patch('flask.request', request_data):
                BenchmarkTest00156_post()
        except Exception:
            # Only around the target function call
            return
        
        # 5. ORACLE CHECK
        for call in mock_eval.call_args_list:
            captured = None
            # Check call.args[0] first
            if len(call.args) > 0:
                captured = call.args[0]
            else:
                # Fall back to call.kwargs.get("None")
                # But since target_arg_name is None, we don't have a name
                # This seems like an error in the oracle context
                # Let's assume it means we should check if there are any kwargs
                if call.kwargs:
                    # Get the first kwarg value
                    captured = next(iter(call.kwargs.values()))
            
            if captured is not None:
                # Match against every pattern in _COMPILED_PATTERNS
                for pattern in _COMPILED_PATTERNS:
                    if pattern.match(str(captured)):
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "eval(__import__('os').system('ls'))",
    "eval(''.join(chr(i) for i in [101, 118, 97, 108]))",
    "EVAL('import os; os.system(\"whoami\")')",
    "eval( 'exec(\"print(\\\"pwned\\\")\")' )",
    "eval(\"__import__('subprocess').getoutput('id')\")",
    "eval( '\\x65\\x76\\x61\\x6c' )",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_code_injection_testcode_BenchmarkTest00156_py_44"
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