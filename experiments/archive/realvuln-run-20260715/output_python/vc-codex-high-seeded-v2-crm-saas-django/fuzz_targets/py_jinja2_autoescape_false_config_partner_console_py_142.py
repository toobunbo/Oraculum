import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

with atheris.instrument_imports():

    from config.partner_console import acct_jinja_cast_585


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script[\\s>]", re.IGNORECASE),

    re.compile("<img[\\s>]", re.IGNORECASE),

    re.compile("<svg[\\s>]", re.IGNORECASE),

    re.compile("<iframe[\\s>]", re.IGNORECASE),

    re.compile("<body[\\s>]", re.IGNORECASE),

    re.compile("<input[\\s>]", re.IGNORECASE),

    re.compile("<details[\\s>]", re.IGNORECASE),

    re.compile("<marquee[\\s>]", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_JINJA2_AUTOESCAPE_FALSE: unescaped HTML tag survived Jinja2 rendering with autoescape=False — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_jinja_cast_585(request)
# condition        : The rendered template output contains unescaped HTML tags (<script, <img, <svg, <iframe) that would have been escaped to &lt;...&gt; if autoescape were enabled, confirming the autoescape=False bypass allows raw HTML injection into the response.
# capture_what     : return value of acct_jinja_cast_585, which is the HttpResponse containing the Jinja2-rendered body with autoescape=False
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


class _FakeUser:
    def __init__(self, payload):
        self.is_authenticated = False
        self.is_active = True
        self.username = payload
        self.first_name = payload
        self.last_name = payload
        self.email = payload
        self.id = 1


class _FakeRequest:
    def __init__(self, payload):
        from django.http import QueryDict
        self.GET = QueryDict('', mutable=True)
        self.GET['q'] = payload
        self.GET['search'] = payload
        self.GET['name'] = payload
        self.GET['query'] = payload
        self.GET['term'] = payload
        self.GET['key'] = payload
        self.GET['value'] = payload
        self.GET['id'] = payload
        self.GET['filter'] = payload
        self.POST = QueryDict('', mutable=True)
        self.POST['q'] = payload
        self.POST['name'] = payload
        self.POST['content'] = payload
        self.POST['value'] = payload
        self.POST['body'] = payload
        self.POST['description'] = payload
        self.META = {
            'QUERY_STRING': 'q=' + payload,
            'CONTENT_TYPE': 'text/html',
            'HTTP_REFERER': payload,
            'HTTP_USER_AGENT': payload,
            'REMOTE_ADDR': '127.0.0.1',
            'SERVER_NAME': 'localhost',
        }
        self.method = 'GET'
        self.path = '/'
        self.path_info = '/'
        self.user = _FakeUser(payload)
        self.body = payload.encode('utf-8', errors='ignore')
        self.content_type = 'text/html'
        self.COOKIES = {'sessionid': payload}
        self.session = {'data': payload, 'query': payload}
        self.FILES = {}
        self.resolver_match = None
        self.content_params = ''
        self.scheme = 'http'
        self.get_full_path = lambda: '/?q=' + payload
        self.is_secure = False
        self.is_ajax = False


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    request = _FakeRequest(payload)

    try:
        result = acct_jinja_cast_585(request)
    except RuntimeError:
        raise
    except Exception:
        return

    if result is None:
        return

    if hasattr(result, 'content'):
        captured = result.content.decode('utf-8', errors='ignore')
    elif isinstance(result, str):
        captured = result
    elif hasattr(result, '__str__'):
        captured = str(result)
    else:
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=repr(captured[:200]), matched_pattern=match.group()))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "<script>alert(1)</script>",
    "<ScRiPt >alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<img\nsrc=x\nonerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=\"javascript:alert(1)\">",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "<body onload=alert(1)>",
    "<marquee onstart=alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_jinja2_autoescape_false_config_partner_console_py_142"
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