import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hr_portal.settings")
django.setup()

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_jinja_cast_384
    from django.http import HttpRequest, QueryDict


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<script", re.IGNORECASE),

    re.compile("onerror\\s*=", re.IGNORECASE),

    re.compile("onload\\s*=", re.IGNORECASE),

    re.compile("javascript:", re.IGNORECASE),

    re.compile("<img[^>]+onerror", re.IGNORECASE),

    re.compile("<svg[^>]+onload", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_JINJA2_AUTOESCAPE_FALSE: XSS payload survived unescaped in Jinja2 render — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def payroll_jinja_cast_384(request)
# condition        : The HttpResponse content contains an unescaped script tag or XSS event handler, confirming that the Jinja2 template rendered user input with autoescape=False and no sanitization was applied.
# capture_what     : return value of payroll_jinja_cast_384 (HttpResponse object), inspecting its .content for unescaped XSS payload
# skip_hint        : False
# ========================================


_COMMON_PARAM_KEYS = [
    'name', 'employee_name', 'id', 'employee_id', 'amount',
    'department', 'title', 'description', 'note', 'comment',
    'message', 'query', 'search', 'q', 'input', 'data',
    'value', 'text', 'content', 'html', 'field', 'param',
    'payroll_id', 'emp_id', 'emp_name', 'first_name', 'last_name',
    'full_name', 'display_name', 'username', 'email', 'reason',
    'memo', 'remarks', 'notes', 'details', 'info', 'subject',
    'body', 'payload', 'custom_field', 'extra', 'additional',
]


def _build_request(payload):
    request = HttpRequest()
    request.method = 'POST'
    request.META = {
        'CONTENT_TYPE': 'application/x-www-form-urlencoded',
        'REMOTE_ADDR': '127.0.0.1',
    }

    qd_get = QueryDict(mutable=True)
    qd_post = QueryDict(mutable=True)
    for key in _COMMON_PARAM_KEYS:
        qd_get[key] = payload
        qd_post[key] = payload
    qd_get._mutable = False
    qd_post._mutable = False

    request.GET = qd_get
    request.POST = qd_post

    class _FakeUser:
        is_authenticated = True
        is_staff = True
        is_active = True
        id = 1
        username = 'testuser'
    request.user = _FakeUser()

    return request


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    if not payload:
        return

    request = _build_request(payload)

    try:
        response = payroll_jinja_cast_384(request)
    except RuntimeError:
        raise
    except Exception:
        return

    if response is None:
        return

    content = getattr(response, 'content', None)
    if content is None:
        return

    if isinstance(content, bytes):
        content_str = content.decode('utf-8', errors='ignore')
    elif isinstance(content, str):
        content_str = content
    else:
        return

    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(content_str)
        if match:
            captured = content_str[:200]
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "<script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<script >alert(1)</script>",
    "<img src=x onerror =alert(1)>",
    "javascript:alert(1)",
    "<div onerror=alert(1)>test</div>",
    "<body onload=alert(1)>",
    "<IMG SRC=x ONERROR=alert(1)>",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_jinja2_autoescape_false_hr_portal_payroll_operations_py_139"
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