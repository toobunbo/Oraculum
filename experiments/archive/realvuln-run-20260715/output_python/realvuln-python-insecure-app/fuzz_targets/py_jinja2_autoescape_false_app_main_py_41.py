import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-python-insecure-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.main import try_hack_me


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script", re.IGNORECASE),

    re.compile("<img\\s+[^>]*onerror", re.IGNORECASE),

    re.compile("<svg\\s+[^>]*onload", re.IGNORECASE),

    re.compile("<iframe\\s+[^>]*src", re.IGNORECASE),

    re.compile("<body\\s+[^>]*onload", re.IGNORECASE),

    re.compile("<input\\s+[^>]*onfocus", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_JINJA2_AUTOESCAPE_FALSE: XSS via unescaped template render — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "name", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def try_hack_me(name: str)
# condition        : The return value contains unescaped HTML/JS tag fragments (e.g. <script, <img onerror, <svg onload) that were injected via the name parameter, confirming autoescape=False allows raw HTML through
# capture_what     : return value of the try_hack_me function, which is the rendered Jinja2 template output
# skip_hint        : False
# ========================================


# === RETURN_VALUE SKELETON ===
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    name = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    try:
        result = try_hack_me(name)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None or not isinstance(result, str):
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(result)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=result[:512], matched_pattern=match.group()))
    return


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"<script>alert(1)</script>",
    b"<img src=x onerror=alert(1)>",
    b"<ScRiPt>alert(document.cookie)</ScRiPt>",
    b"<svg/onload=alert(1)>",
    b"<img\nsrc=x\nonerror=alert(1)>",
    b"<iframe src=\"javascript:alert(1)\"></iframe>",
    b"<body onload=alert(1)>",
    b"<input onfocus=alert(1) autofocus>",
    b"<SCRIPT >alert(1)</SCRIPT >",
    b"<img src=x\t\tonerror=alert(1)>",
    b"<svg\nonload=alert(1)>",
    b"<iMg sRc=x oNeRrOr=alert(1)>",
    b"<body\n\nonload=alert(1)>",
    b"<input\tautofocus\tonfocus=alert(1)>",
    b"<iframe\nsrc=javascript:alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-python-insecure-app/fuzz_corpus/py_jinja2_autoescape_false_app_main_py_41"
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