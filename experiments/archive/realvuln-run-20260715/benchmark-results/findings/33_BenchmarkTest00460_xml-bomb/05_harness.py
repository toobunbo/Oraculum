# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xml-bomb
# function : BenchmarkTest00460_post
# file     : testcode/BenchmarkTest00460.py
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

    from testcode.BenchmarkTest00460 import BenchmarkTest00460_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("(?:<!DOCTYPE\\s+\\w+\\s+\\[\\s*)?(?:<!ENTITY\\s+\\w+\\s+\"(?:[^\"&]|&\\w+;)*\"\\s*){5,}", re.DOTALL | re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : xml.dom.minidom.parseString
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00460_post()
# condition        : {'type': 'regex', 'pattern': '(?:<!DOCTYPE\\s+\\w+\\s+\\[\\s*)?(?:<!ENTITY\\s+\\w+\\s+"(?:[^"&]|&\\w+;)*"\\s*){5,}', 'flags': 'DOTALL|IGNORECASE'}
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
#    - Patch `xml.dom.minidom.parseString` using `with patch(...) as mock_get:`.
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
    # We simulate a basic flask request with a data field
    request_data = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    
    # Create a mock request object
    class MockRequest:
        def __init__(self, data):
            self.data = data.encode('utf-8')
            self.form = {}
            self.args = {}
            self.headers = {}
    
    mock_request = MockRequest(request_data)
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip
    
    # 3. MOCK SETUP
    with patch('xml.dom.minidom.parseString', return_value=MagicMock()) as mock_parse:
        try:
            # Create an instance of the test class
            test_instance = BenchmarkTest00460_post()
            
            # Replace the request attribute with our mock
            original_request = None
            if hasattr(test_instance, 'request'):
                original_request = test_instance.request
                
            test_instance.request = mock_request
            
            # Call the target method
            test_instance.post()
            
            # Restore original request if needed
            if original_request is not None:
                test_instance.request = original_request
                
        except RuntimeError:
            raise  # Never swallow oracle signals
        except Exception:
            return  # Only around the target function call
    
    # 4. ORACLE CHECK
    for call in mock_parse.call_args_list:
        # Get the captured argument
        captured = None
        if call.args:
            captured = call.args[0]  # First positional argument
        elif call.kwargs:
            captured = call.kwargs.get("None")  # Fallback to keyword argument
            
        if captured is not None:
            # Convert to string if needed
            if isinstance(captured, bytes):
                try:
                    captured = captured.decode('utf-8')
                except UnicodeDecodeError:
                    continue  # Skip invalid UTF-8
                    
            # Match against every pattern in _COMPILED_PATTERNS
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))
    
    # 5. EXCEPTION HANDLING
    # Already handled above with specific exception handling


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    '<!DOCTYPE test [ <!ENTITY e1 "test"> <!ENTITY e2 "test"> <!ENTITY e3 "test"> <!ENTITY e4 "test"> <!ENTITY e5 "test"> ]>',
    '<!doctype test [ <!entity e1 "test"> <!entity e2 "test"> <!entity e3 "test"> <!entity e4 "test"> <!entity e5 "test"> ]>',
    '<!DOCTYPE  test  [  <!ENTITY  e1  "test"  >  <!ENTITY  e2  "test"  >  <!ENTITY  e3  "test"  >  <!ENTITY  e4  "test"  >  <!ENTITY  e5  "test"  >  ]>',
    '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY e1 "test"> <!ENTITY e2 "test"> <!ENTITY e3 "test"> <!ENTITY e4 "test"> <!ENTITY e5 "test"> ]>',
    '<!DOCTYPE test[<!ENTITY e1 "test"><!ENTITY e2 "test"><!ENTITY e3 "test"><!ENTITY e4 "test"><!ENTITY e5 "test">]>',
    '<!DOCTYPE test [<!ENTITY e1 "a&entity;"> <!ENTITY entity "test"> <!ENTITY e2 "test"> <!ENTITY e3 "test"> <!ENTITY e4 "test"> <!ENTITY e5 "test"> ]>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_xml_bomb_testcode_BenchmarkTest00460_py_45"
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