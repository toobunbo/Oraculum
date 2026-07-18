import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnpy"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from src.vulnpy.django.vulnerable_asgi import get_trigger_view


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script[\\s>]", re.IGNORECASE),

    re.compile("javascript\\s*:", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("<img[^>]+onerror", re.IGNORECASE),

    re.compile("<svg[^>]+onload", re.IGNORECASE),

    re.compile("onmouse\\w+\\s*=", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: unescaped XSS payload in HttpResponse content — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "trigger", "index": 1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def get_trigger_view(name, trigger)
# condition        : The returned HttpResponse content contains raw HTML/JavaScript injection fragments (e.g., <script tags, event handlers like onerror=) that were passed as the trigger parameter, confirming no escaping was applied before rendering.
# capture_what     : return value of get_trigger_view, specifically the .content attribute of the HttpResponse object decoded to string
# skip_hint        : False
# ========================================


# === RETURN_VALUE SKELETON ===


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    if len(data) < 2:
        return

    half = len(data) // 2
    name = fdp.ConsumeBytes(half).decode('utf-8', errors='ignore')
    trigger = fdp.ConsumeRemainingBytes().decode('utf-8', errors='ignore')

    try:
        response = get_trigger_view(name, trigger)
    except RuntimeError:
        raise
    except Exception:
        return

    if response is None:
        return

    try:
        content_bytes = response.content
    except Exception:
        return

    if content_bytes is None:
        return

    if isinstance(content_bytes, bytes):
        captured = content_bytes.decode('utf-8', errors='ignore')
    elif isinstance(content_bytes, str):
        captured = content_bytes
    else:
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(
                _RAISE_MESSAGE.format(
                    captured=repr(captured[:512]),
                    matched_pattern=match.group()
                )
            )



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"<ScRiPt >alert(1)</ScRiPt>",
    b"<script\t\n>alert(1)</script>",
    b"<img src=x onerror\t\n=alert(1)>",
    b"<svg\n\nonload=alert(1)>",
    b"<a href=\"java\tscript:alert(1)\">click</a>",
    b"<img src=x OnErRoR=alert(1)>",
    b"<div onmouseover =alert(1)>hover</div>",
    b"<svg/onload=alert(1)>",
    b"<SCRIPT\nSRC=//evil.com/x.js>",
    b"<img src=x onerror\n=alert(1)//>",
    b"<body onload=alert(1)>",
    b"<input onfocus=alert(1) autofocus>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vulnpy/fuzz_corpus/py_reflective_xss_src_vulnpy_django_vulnerable_asgi_py_57"
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