# AUTO-GENERATED ATHERIS HARNESS — Flask framework (DETERMINISTIC, no LLM fill)
# rule_id  : py/url-redirection
# function : BenchmarkTest00067_post  (route handler nested in init(app))
# file     : testcode/BenchmarkTest00067.py
# input    : cookie key="BenchmarkTest00067"
# sink     : flask.redirect
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock
from flask import Flask


REPO_ROOT = "/home/trieudai/bench-src"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    import testcode.BenchmarkTest00067 as _target_mod


# === Flask framework setup =====================================================
# OWASP Benchmark nests the vulnerable handler inside ``def init(app):`` and
# registers it via ``@app.route``. We import the module, build a throwaway app,
# call ``init(app)`` to register routes, then pull the handler back out.
_app = Flask(__name__)
_target_mod.init(_app)
_HANDLER = _app.view_functions["BenchmarkTest00067_post"]

# === Oracle contracts ==========================================================
_COMPILED_PATTERNS = [

    re.compile("//", re.IGNORECASE),

    re.compile("javascript:", re.IGNORECASE),

    re.compile("\\\\", re.IGNORECASE),

    re.compile("%2f%2f", re.IGNORECASE),

]
_RAISE_MESSAGE = "ORACULUM_VIOLATION: captured={captured}"
_PATCH_TARGET = "flask.redirect"
_INPUT_KIND = "cookie"
_INPUT_KEY = "BenchmarkTest00067"


def _request_context(payload):
    """Build a Flask test request context that exposes ``payload`` as the
    tainted request value, chosen by the detected input source."""
    if _INPUT_KIND == "form":
        return _app.test_request_context(
            "/", method="POST", data={_INPUT_KEY: payload} if _INPUT_KEY else {"x": payload}
        )
    if _INPUT_KIND == "args":
        return _app.test_request_context(
            "/", method="GET", query_string={_INPUT_KEY: payload} if _INPUT_KEY else {"x": payload}
        )
    if _INPUT_KIND == "cookie":
        cookie = f"{_INPUT_KEY}={payload}" if _INPUT_KEY else f"x={payload}"
        return _app.test_request_context("/", method="POST", headers={"Cookie": cookie})
    if _INPUT_KIND == "header":
        return _app.test_request_context(
            "/", method="POST", headers={_INPUT_KEY: payload} if _INPUT_KEY else {"X-X": payload}
        )
    if _INPUT_KIND == "path":
        # Route handlers that read request.path: carry the payload in the URL.
        return _app.test_request_context(f"/{payload}", method="GET")
    # view_args / unknown — fall back to a form value.
    return _app.test_request_context(
        "/", method="POST", data={_INPUT_KEY or "x": payload}
    )


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    payload = fdp.ConsumeBytes(1024).decode("utf-8", errors="ignore")
    with patch(_PATCH_TARGET) as _mock:
        _mock.return_value = MagicMock()
        with _request_context(payload):
            try:
                _HANDLER()
            except RuntimeError:
                raise
            except Exception:
                pass
        # Oracle: inspect what reached the patched sink.
        for _call in _mock.call_args_list:
            if _call.args:
                _captured = _call.args[0]
            elif "args" in _call.kwargs:
                _captured = _call.kwargs["args"]
            elif _call.kwargs:
                _captured = next(iter(_call.kwargs.values()))
            else:
                continue
            _captured_str = str(_captured)
            for _pat in _COMPILED_PATTERNS:
                if _pat.search(_captured_str):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(_captured_str)))


# === SEED CORPUS ===============================================================
_SEED_CORPUS = [

    "//attacker.example/x",

    "https://attacker.example/",

    "javascript:alert(1)",

    "%2f%2fattacker.example",

]


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/benchmark-python/fuzz_corpus/py_url_redirection_testcode_BenchmarkTest00067_py_47"
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