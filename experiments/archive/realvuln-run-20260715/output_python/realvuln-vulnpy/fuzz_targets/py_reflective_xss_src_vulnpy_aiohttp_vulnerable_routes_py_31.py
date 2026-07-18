import atheris
import sys
import re
import os
import asyncio



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnpy"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from src.vulnpy.aiohttp.vulnerable_routes import get_trigger_view


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script", re.IGNORECASE),

    re.compile("<img[^>]+onerror\\s*=", re.IGNORECASE),

    re.compile("<svg[^>]+onload\\s*=", re.IGNORECASE),

    re.compile("<body[^>]+onload\\s*=", re.IGNORECASE),

    re.compile("javascript\\s*:", re.IGNORECASE),

    re.compile("<iframe[^>]+src\\s*=", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: unescaped XSS payload in HTML response — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "trigger", "index": 1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def get_trigger_view(name, trigger)
# condition        : The response.text contains raw HTML/JS injection payloads (e.g., <script>, <img onerror, <svg onload) that were never escaped, confirming reflective XSS via direct string concatenation into the HTML response.
# capture_what     : return value of get_trigger_view, specifically response.text
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

    if len(data) < 2:
        return

    half = len(data) // 2
    name = fdp.ConsumeBytes(half).decode('utf-8', errors='ignore')
    trigger = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    try:
        result = get_trigger_view(name, trigger)
        if asyncio.iscoroutine(result):
            result = asyncio.run(result)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None:
        return

    try:
        captured = result.text
    except Exception:
        return

    if not isinstance(captured, str):
        return

    for pattern in _COMPILED_PATTERNS:
        m = pattern.search(captured)
        if m:
            raise RuntimeError(_RAISE_MESSAGE.format(
                captured=captured[:500],
                matched_pattern=pattern.pattern
            ))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror =alert(1)>",
    "<svg/onload=alert(1)>",
    "<body\nonload=alert(1)>",
    "java\tscript:alert(1)",
    "<iframe\nsrc=javascript:alert(1)>",
    "<<script>script>alert(1)</script>",
    "<img src=x\tonerror\t=\talert(1)>",
    "<SVG\nONLOAD=alert(1)>",
    "<iMg sRc=x oNeRrOr=alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnpy/fuzz_corpus/py_reflective_xss_src_vulnpy_aiohttp_vulnerable_routes_py_31"
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