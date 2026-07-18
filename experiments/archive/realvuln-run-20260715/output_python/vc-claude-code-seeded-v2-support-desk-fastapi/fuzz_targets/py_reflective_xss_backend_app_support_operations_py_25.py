import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-support-desk-fastapi"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from backend.app.support_operations import ticket_copy_badge_028


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script[^>]*>", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("onclick\\s*=", re.IGNORECASE),

    re.compile("onmouseover\\s*=", re.IGNORECASE),

    re.compile("javascript:", re.IGNORECASE),

    re.compile("<img[^>]+onerror", re.IGNORECASE),

    re.compile("<svg[^>]+onload", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: unescaped XSS payload in HTMLResponse body — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "copyline", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def ticket_copy_badge_028(copyline: str, gate_ref: None)
# condition        : The returned HTMLResponse body contains unescaped XSS payloads (script tags or event handlers) injected via the copyline parameter, confirming no sanitization is applied
# capture_what     : return value of ticket_copy_badge_028, specifically the HTML body inside the HTMLResponse
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

    copyline = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    try:
        result = ticket_copy_badge_028(copyline, None)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None:
        return

    if hasattr(result, 'body'):
        captured = result.body
        if isinstance(captured, bytes):
            captured = captured.decode('utf-8', errors='ignore')
        elif not isinstance(captured, str):
            return
    elif isinstance(result, str):
        captured = result
    elif isinstance(result, bytes):
        captured = result.decode('utf-8', errors='ignore')
    else:
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=match.group(), matched_pattern=pattern.pattern))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    '<ScRiPt>alert(1)</ScRiPt>',
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<a href=javascript:alert(1)>click</a>',
    '<div onclick=alert(1)>click</div>',
    '<img src=x onerror = alert(1)>',
    '<SVG ONLOAD=alert(1)>',
    '<script >alert(1)</script >',
    '<img\nsrc=x\nonerror=alert(1)>',
    '<<script>script>alert(1)</script>',
    '<img src=x onerror\t=\talert(1)>',
    '<svg\x00onload=alert(1)>',
    '<iMg SrC=x oNeRrOr=alert(1)>',
    '<body onmouseover=alert(1)>',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-support-desk-fastapi/fuzz_corpus/py_reflective_xss_backend_app_support_operations_py_25"
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