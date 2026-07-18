# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xml-bomb
# function : BenchmarkTest00459_post
# file     : testcode/BenchmarkTest00459.py
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

    from testcode.BenchmarkTest00459 import BenchmarkTest00459_post


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(".*<!DOCTYPE.*\\[.*<!ENTITY.*>.*\\].*>.*", re.IGNORECASE),

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
# signature        : def BenchmarkTest00459_post()
# condition        : {'type': 'regex', 'pattern': '.*<!DOCTYPE.*\\[.*<!ENTITY.*>.*\\].*>.*', 'match_group': 0}
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
    request_data = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    
    # Early exit for empty or irrelevant inputs
    if not request_data:
        return

    # 2. SKIP CONDITION
    # skip_hint is False, so we don't apply any early return here

    # 3. MOCK SETUP
    with patch("xml.dom.minidom.parseString", return_value=MagicMock()) as mock_parseString:
        try:
            # Create a mock Flask request object
            class MockRequest:
                def __init__(self, data):
                    self.data = data.encode('utf-8')
                    self.form = {}
                    self.args = {}
                    self.json = None
                    self.values = {}
            
            mock_request = MockRequest(request_data)

            # Temporarily replace the request in the module
            import testcode.BenchmarkTest00459
            original_request = getattr(testcode.BenchmarkTest00459, 'request', None)
            testcode.BenchmarkTest00459.request = mock_request

            # Call the target function
            BenchmarkTest00459_post()

            # Restore original request
            if original_request is not None:
                testcode.BenchmarkTest00459.request = original_request
            else:
                delattr(testcode.BenchmarkTest00459, 'request')

        except Exception:
            # Restore original request even if exception occurs
            if original_request is not None:
                testcode.BenchmarkTest00459.request = original_request
            elif hasattr(testcode.BenchmarkTest00459, 'request'):
                delattr(testcode.BenchmarkTest00459, 'request')
            return

        # 4. ORACLE CHECK
        for call in mock_parseString.call_args_list:
            # Get the first argument (XML string)
            captured = None
            if call.args:
                captured = call.args[0]
            elif call.kwargs:
                captured = call.kwargs.get("None")  # fallback as per spec
            
            if captured is None:
                continue

            # Match against every pattern in _COMPILED_PATTERNS
            for pattern in _COMPILED_PATTERNS:
                if pattern.match(str(captured)):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>',
    '<!doctype test [ <!entity xxe system "file:///etc/passwd"> ]><test>&xxe;</test>',
    '<!DOCTYPE test[<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>',
    '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    '<![CDATA[<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>]]>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_xml_bomb_testcode_BenchmarkTest00459_py_51"
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