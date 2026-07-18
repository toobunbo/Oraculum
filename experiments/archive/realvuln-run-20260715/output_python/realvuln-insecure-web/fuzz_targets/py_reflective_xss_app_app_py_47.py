import atheris
import sys
import re
import os

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-insecure-web"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from app.app import dashboard
    from app.app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("javascript:", re.IGNORECASE),

    re.compile("<img[^>]+src\\s*=", re.IGNORECASE),

    re.compile("<svg[^>]+onload", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_REFLECTIVE_XSS: unescaped HTML/JS in return value — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "session", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def dashboard()
# condition        : The return value contains an unescaped HTML/JS injection payload derived from the user-controlled cookie value, confirming reflective XSS.
# capture_what     : return value of the dashboard function
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<script\t>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    '<a href="javascript:alert(1)">click</a>',
    "\x00<script>alert(1)</script>",
    "<img/src=x/onerror=alert(1)>",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    param_session = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    with app.test_request_context('/', headers={'Cookie': 'session=' + param_session}):
        try:
            result = dashboard()
        except RuntimeError:
            raise
        except Exception:
            return

    if result is None:
        return

    if hasattr(result, 'data'):
        result = result.data
    if isinstance(result, bytes):
        result = result.decode('utf-8', errors='ignore')
    if not isinstance(result, str):
        return

    for pattern in _COMPILED_PATTERNS:
        m = pattern.search(result)
        if m:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=result[:200], matched_pattern=pattern.pattern))


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-insecure-web/fuzz_corpus/py_reflective_xss_app_app_py_47"
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