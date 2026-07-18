# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/jinja2/autoescape-false
# function : read_root
# file     : main.py
# ================================================================
import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-pythonssti"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from main import read_root


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script[^>]*>", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("onclick\\s*=", re.IGNORECASE),

    re.compile("javascript\\s*:", re.IGNORECASE),

    re.compile("<img[^>]+onerror", re.IGNORECASE),

    re.compile("<svg[^>]+onload", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_JINJA2_AUTOESCAPE_FALSE: XSS payload survived Jinja2 render without autoescape — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "username", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def read_root(username)
# condition        : The rendered return value contains unescaped HTML/JavaScript XSS payloads such as script tags or event handlers, confirming that autoescape=False allows injection to survive rendering.
# capture_what     : return value of read_root containing the rendered Jinja2 template output
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
    
    username = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    try:
        result = read_root(username)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None:
        return

    if isinstance(result, str):
        captured = result
    elif isinstance(result, dict):
        captured = str(result.get('body', result.get('html', result.get('response', ''))))
    elif isinstance(result, (list, tuple)):
        captured = str(result[0]) if len(result) > 0 else ''
    else:
        captured = str(result)

    if not captured:
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(
                _RAISE_MESSAGE.format(
                    captured=repr(captured[:500]),
                    matched_pattern=pattern.pattern
                )
            )



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b"<script>alert(1)</script>",
    b"<ScRiPt>alert(1)</ScRiPt>",
    b"<img src=x onerror=alert(1)>",
    b"<svg/onload=alert(1)>",
    b"<img src=x onerror  =  alert(1)>",
    b"<img\nsrc=x\nonerror=\nalert(1)>",
    b"<SCRIPT >alert(1)</SCRIPT >",
    b"<svg\u000aonload=alert(1)>",
    b"<img src=x oNeRrOr=alert(1)>",
    b"<script\x00>alert(1)</script>",
    b"<svg onload=alert(1)>",
    b"<img src=1 onerror =\"alert(1)\">",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-pythonssti/fuzz_corpus/py_jinja2_autoescape_false_main_py_11"
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