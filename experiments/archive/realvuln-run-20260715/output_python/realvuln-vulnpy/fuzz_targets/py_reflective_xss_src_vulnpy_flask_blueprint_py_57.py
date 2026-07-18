import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnpy"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from src.vulnpy.flask.blueprint import get_trigger_view


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script[\\s>]", re.IGNORECASE),

    re.compile("on\\w+\\s*=", re.IGNORECASE),

    re.compile("javascript\\s*:", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: unescaped XSS payload in return value — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "trigger", "index": 1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def get_trigger_view(name, trigger)
# condition        : The returned HTML string contains unescaped script tags or event handler attributes, confirming that user input was concatenated without sanitization
# capture_what     : return value of get_trigger_view containing the concatenated HTML template with user input
# skip_hint        : trigger is None or not isinstance(trigger, str) or len(trigger) == 0
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

    if len(data) < 2:
        return

    # Generate name (first string param) - use half the data
    name = fdp.ConsumeBytes(len(data) // 2).decode('utf-8', errors='ignore')

    # Generate trigger (last string param) - consumes all remaining bytes
    trigger = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    # Skip condition: trigger is None or not isinstance(trigger, str) or len(trigger) == 0
    if trigger is None or not isinstance(trigger, str) or len(trigger) == 0:
        return

    try:
        result = get_trigger_view(name, trigger)
    except RuntimeError:
        raise
    except Exception:
        return

    # Check return value is a string
    if result is None or not isinstance(result, str):
        return

    # Oracle check - OUTSIDE try/except
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            captured = result[:200]
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "x" * 50 + "<script>alert(1)</script>",
    "a" * 50 + "<ScRiPt>alert(1)</ScRiPt>",
    "b" * 50 + "<img src=x onerror=alert(1)>",
    "c" * 50 + "<div OnClIcK=alert(1)>x</div>",
    "d" * 50 + '<a href="javascript:alert(1)">x</a>',
    "e" * 50 + "<script\t\n>alert(1)</script>",
    "f" * 50 + "<svg/onload=alert(1)>",
    "g" * 50 + "<SCRIPT >alert(1)</SCRIPT>",
    "h" * 50 + "<body onload =alert(1)>",
    "i" * 50 + "JAVASCRIPT:alert(1)",
    "j" * 50 + "<script\n\r>alert(1)</script>",
    "k" * 50 + "<input onfocus=alert(1) autofocus>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnpy/fuzz_corpus/py_reflective_xss_src_vulnpy_flask_blueprint_py_57"
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