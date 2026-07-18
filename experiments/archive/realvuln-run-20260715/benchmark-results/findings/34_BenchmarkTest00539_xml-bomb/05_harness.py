# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xml-bomb
# function : BenchmarkTest00539_post
# file     : testcode/BenchmarkTest00539.py
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

    from testcode.BenchmarkTest00539 import BenchmarkTest00539_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("[\\s\\S]+", re.IGNORECASE),

]
_RAISE_MESSAGE  = "ORACULUM_VIOLATION: captured={captured}"
_TAINTED_PARAMS = [{"name": "request", "index": -1, "type": "flask_request"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : xml.dom.minidom.parseString
# target_arg_index : 0
# target_arg_name  : bar
# input_strategy   : flask_view
# signature        : def BenchmarkTest00539_post()
# condition        : oracle condition
# capture_what     : bar
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
#    - For each call: check call.args[0] first,
#      fall back to call.kwargs.get("bar").
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
    try:
        request_data = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    except Exception:
        return

    # 2. SKIP CONDITION (none specified, so skip_hint is False)

    # 3. MOCK SETUP
    with patch("xml.dom.minidom.parseString", return_value=MagicMock()) as mock_get:
        try:
            # Create a mock Flask request object
            class MockRequest:
                def __init__(self, data):
                    self.data = data.encode('utf-8')
                    self.form = {}
                    self.args = {}
                    self.json = None
                    self.values = {}
            
            # Create a mock request with our fuzzed data
            mock_request = MockRequest(request_data)
            
            # Call the target function with the mock request
            BenchmarkTest00539_post(mock_request)
            
        except Exception:
            # Catch any exceptions from the target function and return to avoid crashing the fuzzer
            return

    # 4. ORACLE CHECK
    for call in mock_get.call_args_list:
        # Get the captured argument (first positional argument or named 'bar')
        captured = None
        if call.args:
            captured = call.args[0]
        elif 'bar' in call.kwargs:
            captured = call.kwargs['bar']
        
        if captured is not None:
            # Check against all patterns
            for pattern in _COMPILED_PATTERNS:
                if pattern.match(str(captured)):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"http://example.com/\">]><test>&xxe;</test>",
    "<root><![CDATA[<script>alert(1)</script>]]></root>",
    "<root xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></root>",
    "<root>&lt;script&gt;alert(1)&lt;/script&gt;</root>",
    "<root><![CDATA[<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]]]><![CDATA[><foo>&xxe;</foo>]]></root>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_xml_bomb_testcode_BenchmarkTest00539_py_49"
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