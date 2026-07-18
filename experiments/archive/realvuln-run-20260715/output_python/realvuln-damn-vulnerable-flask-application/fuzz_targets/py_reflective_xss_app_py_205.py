import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-damn-vulnerable-flask-application"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app import sayhi
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script[^>]*>", re.IGNORECASE),

    re.compile("</script>", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("onclick\\s*=", re.IGNORECASE),

    re.compile("javascript\\s*:", re.IGNORECASE),

    re.compile("<img[^>]+onerror", re.IGNORECASE),

    re.compile("<svg[^>]+onload", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE-XSS: unescaped XSS payload in rendered output — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "name", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def sayhi()
# condition        : The returned HTML string contains unescaped HTML/JS injection fragments such as <script> tags or event handler attributes, confirming that user input in the name parameter survived render_template_string without escaping.
# capture_what     : return value of the sayhi Flask view function (rendered HTML string)
# skip_hint        : False
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
    
    param_name = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "name": param_name,
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        try:
            result = sayhi()
        except RuntimeError:
            raise
        except Exception:
            return

    # 4. Extract string content from return value
    if result is None or not isinstance(result, str):
        return

    # 5. Oracle check — OUTSIDE the function call try/except
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            captured = match.group(0)
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"<script>alert(1)</script>",
    b"<ScRiPt>alert(1)</ScRiPt>",
    b"<script >alert(1)</script >",
    b'<img src=x onerror=alert(1)>',
    b'<svg onload=alert(1)>',
    b'<a href="javascript:alert(1)">click</a>',
    b'<div onerror =alert(1)>',
    b'<img/src=x/onerror=alert(1)>',
    b'<script\tonerror=alert(1)>',
    b'<scr\x00ipt>alert(1)</scr\x00ipt>',
    b'<SCRIPT >alert(1)</SCRIPT >',
    b'<svg/onload=alert(1)>',
    b'<img src=x ONERROR=alert(1)>',
    b'<body onload=alert(1)>',
    b'<input onfocus=alert(1) autofocus>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-flask-application/fuzz_corpus/py_reflective_xss_app_py_205"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed.encode("utf-8") if isinstance(_seed, str) else _seed)

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()