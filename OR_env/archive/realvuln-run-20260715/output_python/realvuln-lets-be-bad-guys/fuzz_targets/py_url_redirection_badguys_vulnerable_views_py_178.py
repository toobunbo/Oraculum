import atheris
import sys
import re
import os
import io
from urllib.parse import quote



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-lets-be-bad-guys"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "badguys.settings")
django.setup()

with atheris.instrument_imports():

    from badguys.vulnerable.views import unvalidated_redirect
    from django.core.handlers.wsgi import WSGIRequest


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("https?://evil\\.com", re.IGNORECASE),

    re.compile("https?://attacker\\.com", re.IGNORECASE),

    re.compile("https?://malicious\\.site", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_URL-REDIRECTION: unvalidated open redirect detected — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "WSGIRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def unvalidated_redirect(request)
# condition        : The returned HttpResponseRedirect object contains an http:// or https:// URL in its url attribute, confirming that an arbitrary external URL passed the redirect sink without any validation
# capture_what     : return value of unvalidated_redirect, which is an HttpResponseRedirect object whose url attribute contains the unvalidated user-provided URL
# skip_hint        : False
# ========================================


def _make_request(url):
    encoded = quote(url, safe='')
    query_string = "next={}&url={}&redirect_to={}&redirect={}&target={}".format(
        encoded, encoded, encoded, encoded, encoded
    )
    environ = {
        'REQUEST_METHOD': 'GET',
        'QUERY_STRING': query_string,
        'PATH_INFO': '/',
        'SERVER_NAME': 'localhost',
        'SERVER_PORT': '80',
        'wsgi.input': io.BytesIO(b''),
        'wsgi.url_scheme': 'http',
    }
    return WSGIRequest(environ)


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.

    url = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    if not url:
        return

    request = _make_request(url)

    try:
        result = unvalidated_redirect(request)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None:
        return

    captured = getattr(result, 'url', None)
    if captured is None or not isinstance(captured, str):
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.group()))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "https://evil.com",
    "HTTPS://EVIL.COM",
    "https://attacker.com",
    "http://malicious.site",
    "https://evil.com/",
    "https://attacker.com/path/to/page",
    "https://malicious.site?param=value",
    "http://evil.com#@example.com",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-lets-be-bad-guys/fuzz_corpus/py_url_redirection_badguys_vulnerable_views_py_178"
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