# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/reflective-xss
# function : xml
# file     : app.py
# ================================================================
import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-damn-vulnerable-flask-application"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app import xml
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("javascript\\s*:", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE-XSS: XSS payload survived XML round-trip in return value — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "xml", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def xml()
# condition        : The returned HTML string contains unescaped HTML/JavaScript tags or event handler attributes that survived the XML parse-to-string round-trip, confirming XSS injection
# capture_what     : return value of the xml() Flask view function containing the rendered HTML response
# skip_hint        : len(xml) < 3
# ========================================


# === RETURN_VALUE SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Call target function directly and capture the return value.
# 4. Extract string content from the return value (based on capture_what).
# 5. Compare captured string against _COMPILED_PATTERNS.
# 6. Propagate RuntimeError; swallow other exceptions.
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.
    
    # 1. Generate inputs from fdp
    
    param_xml = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    # 2. Skip condition
    if len(param_xml) < 3:
        return
    
    query_params = {
        
        "xml": param_xml,
        
    }
    
    # 3. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        try:
            result = xml()
        except RuntimeError:
            raise
        except Exception:
            return
    
    # 4. Extract string content from the return value
    if result is None:
        return
    
    captured = None
    if isinstance(result, str):
        captured = result
    elif hasattr(result, 'get_data'):
        captured = result.get_data(as_text=True)
    elif isinstance(result, tuple):
        first = result[0]
        if isinstance(first, str):
            captured = first
        elif hasattr(first, 'get_data'):
            captured = first.get_data(as_text=True)
    
    if captured is None or not isinstance(captured, str):
        return
    
    # 5. Oracle check — OUTSIDE the function call try/except
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(
                _RAISE_MESSAGE.format(captured=captured[:200], matched_pattern=match.group())
            )
    


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script\t>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror\t=\talert(1)>",
    "<a href=javascript:alert(1)>click</a>",
    "<svg onload=alert(1)>",
    "<svg\tonload=alert(1)>",
    "<IMG SRC=x ONERROR=alert(1)>",
    "<ScRiPt >alert(1)</ScRiPt >",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-flask-application/fuzz_corpus/py_reflective_xss_app_py_163"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                if isinstance(_seed, bytes):
                    _f.write(_seed)
                else:
                    _f.write(_seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()