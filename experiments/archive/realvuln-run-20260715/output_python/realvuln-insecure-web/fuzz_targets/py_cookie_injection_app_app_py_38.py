import atheris
import sys
import re
import os

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-insecure-web"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from app.app import login, app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("Set-Cookie.*session=[^;]*;", re.IGNORECASE),

    re.compile("Set-Cookie.*session=[^;]*=([^;]|$)", re.IGNORECASE),

    re.compile("Set-Cookie.*session=FIXATED_SESSION", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COOKIE_INJECTION: unsanitized cookie value in response — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "username", "index": -1, "type": "str"}, {"name": "password", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def login()
# condition        : The returned Flask response contains a Set-Cookie header where the session cookie value includes semicolons or other cookie-attribute-injection characters, confirming that raw user input passed through to the cookie value without sanitization
# capture_what     : return value of the login function (Flask response object)
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    "admin; Path=/",
    "admin; HttpOnly; Secure",
    "ADMIN; DOMAIN=EVIL.COM",
    "admin\t;\tPath=/",
    "admin%3BPath%3D%2F",
    "admin\uFF1BPath=evil",
    "admin\x00; Path=/",
    "FIXATED_SESSION",
    "admin ;\nPath=/",
    "admin;SameSite=None",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    param_username = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    param_password = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    query_params = {
        "username": param_username,
        "password": param_password,
    }

    response = None
    try:
        with app.test_request_context(query_string=query_params):
            response = login()
    except RuntimeError:
        raise
    except Exception:
        return

    if response is None:
        return

    captured = ""
    try:
        cookie_headers = response.headers.getlist("Set-Cookie")
        captured = "\n".join(cookie_headers)
    except Exception:
        return

    if not captured:
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.group()))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-insecure-web/fuzz_corpus/py_cookie_injection_app_app_py_38"
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