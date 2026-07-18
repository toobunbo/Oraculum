import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-flask-xss"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app.blueprints.xss_protection.views import index
    from app import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("^//", re.IGNORECASE),

    re.compile("^javascript:", re.IGNORECASE),

    re.compile("https?://evil\\.com", re.IGNORECASE),

    re.compile("https?://attacker\\.com", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_URL-REDIRECTION: open redirect bypass detected — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "next", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def index()
# condition        : The Location header in the redirect response contains an untrusted external URL (protocol-relative, javascript:, or explicit external http/https scheme to attacker-controlled domain), confirming no sanitization is applied to the user-provided 'next' parameter.
# capture_what     : Location header value from the Flask Response object returned by redirect()
# skip_hint        : False
# ========================================


# === RETURN_VALUE SKELETON ===



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    # 1. Generate inputs from fdp
    param_next = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    
    query_params = {
        "next": param_next,
    }
    
    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_params):
        try:
            response = index()
        except RuntimeError:
            raise
        except Exception:
            return

    # 4. Extract Location header from the returned Flask Response
    if response is None:
        return
    if not hasattr(response, 'headers'):
        return

    location = response.headers.get("Location")
    if location is None or not isinstance(location, str):
        return

    # 5. Oracle check — OUTSIDE the try/except
    for pattern in _COMPILED_PATTERNS:
        m = pattern.search(location)
        if m:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=location, matched_pattern=pattern.pattern))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "//evil.com/path",
    "JAVASCRIPT:alert(1)",
    "https://evil.com/steal",
    "//attacker.com",
    "  javascript:alert(1)",
    "https://ATTACKER.com/login",
    "java\tscript:alert(1)",
    "//Evil.Com",
    "http://evil.com",
    "HTTPS://evil.com",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-flask-xss/fuzz_corpus/py_url_redirection_app_blueprints_xss_protection_views_py_12"
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