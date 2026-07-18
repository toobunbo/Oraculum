import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-insecure-web"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.app import search
    from app.app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script", re.IGNORECASE),

    re.compile("<img\\s+[^>]*onerror", re.IGNORECASE),

    re.compile("<svg\\s+[^>]*onload", re.IGNORECASE),

    re.compile("javascript:", re.IGNORECASE),

    re.compile("<iframe", re.IGNORECASE),

    re.compile("<body\\s+[^>]*onload", re.IGNORECASE),

    re.compile("onmouseover\\s*=", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: unescaped XSS payload in return value — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "q", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def search()
# condition        : The return value contains an unescaped HTML tag or XSS payload fragment injected via the query parameter, confirming no sanitization is applied
# capture_what     : return value of the search function containing the f-string interpolated HTML response
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
    
    param_q = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        
        "q": param_q,
        
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        try:
            result = search()
        except RuntimeError:
            raise
        except Exception:
            return

    # 4. Extract string content from the return value
    if result is None:
        return
    if not isinstance(result, str):
        return

    # 5. Compare captured string against _COMPILED_PATTERNS
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            captured = match.group(0)
            raise RuntimeError(
                _RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern)
            )



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"<ScRiPt>alert(1)</ScRiPt>",
    b"<img    src=x   onerror=alert(1)>",
    b"<svg/onload=alert(1)>",
    b"<iframe src=\"javascript:alert(1)\">",
    b"<body\nonload=alert(1)>",
    b"<img src=x oNeRrOr=alert(1)>",
    b"<<script>script>alert(1)</script>",
    b"\"onmouseover=\"alert(1)",
    b"<scr\x00ipt>alert(1)</script>",
    b"<svg\x09\x0a\x0d onload=alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-insecure-web/fuzz_corpus/py_reflective_xss_app_app_py_53"
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