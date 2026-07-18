import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_crumb_lane_290


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(";\\s*Path\\s*=", re.IGNORECASE),

    re.compile(";\\s*Domain\\s*=", re.IGNORECASE),

    re.compile(";\\s*Secure", re.IGNORECASE),

    re.compile(";\\s*HttpOnly", re.IGNORECASE),

    re.compile(";\\s*SameSite\\s*=", re.IGNORECASE),

    re.compile(";\\s*Expires\\s*=", re.IGNORECASE),

    re.compile(";\\s*Max-Age\\s*=", re.IGNORECASE),

    re.compile("\\r?\\n", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COOKIE_INJECTION: unsanitized marker value in Set-Cookie header — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def payroll_crumb_lane_290(request)
# condition        : The returned response's portal_crumb cookie value contains cookie-attribute injection fragments (semicolon-delimited attributes or CRLF sequences), confirming that unsanitized user input reached the Set-Cookie header
# capture_what     : Cookie value of 'portal_crumb' from the returned JsonResponse object's .cookies dict
# skip_hint        : False
# ========================================


class _FakeRequest:
    """Minimal duck-type of Django HttpRequest for fuzzing."""
    def __init__(self, payload):
        self.GET = {
            'crumb': payload, 'value': payload, 'name': payload,
            'token': payload, 'portal_crumb': payload, 'q': payload,
            'id': payload, 'user': payload, 'session': payload,
        }
        self.POST = {
            'crumb': payload, 'value': payload, 'name': payload,
            'token': payload, 'portal_crumb': payload, 'id': payload,
        }
        self.COOKIES = {
            'crumb': payload, 'value': payload,
            'portal_crumb': payload, 'sessionid': payload,
        }
        self.META = {
            'HTTP_X_CRUMB': payload, 'HTTP_X_TOKEN': payload,
            'HTTP_COOKIE': f'portal_crumb={payload}',
            'CONTENT_TYPE': 'application/x-www-form-urlencoded',
            'REMOTE_ADDR': '127.0.0.1',
        }
        self.method = 'GET'
        self.body = payload.encode('utf-8', errors='ignore')
        self.content_type = 'application/x-www-form-urlencoded'
        self.user = _FakeUser()


class _FakeUser:
    def __init__(self):
        self.id = 1
        self.username = 'test'
        self.is_authenticated = True
        self.is_active = True


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    if not payload:
        return

    request = _FakeRequest(payload)

    try:
        response = payroll_crumb_lane_290(request)
    except RuntimeError:
        raise
    except Exception:
        return

    if response is None:
        return

    captured = None

    if hasattr(response, 'cookies') and 'portal_crumb' in response.cookies:
        cookie_obj = response.cookies['portal_crumb']
        if hasattr(cookie_obj, 'value'):
            captured = cookie_obj.value
        elif isinstance(cookie_obj, str):
            captured = cookie_obj
        elif hasattr(cookie_obj, 'coded_value'):
            captured = cookie_obj.coded_value

    if captured is None or not isinstance(captured, str):
        return

    for pattern in _COMPILED_PATTERNS:
        m = pattern.search(captured)
        if m:
            raise RuntimeError(
                _RAISE_MESSAGE.format(captured=captured[:200], matched_pattern=m.group())
            )


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"; Path=/admin".decode('utf-8'),
    b";  DOMAIN  =  .evil.com".decode('utf-8'),
    b"; Secure; HttpOnly".decode('utf-8'),
    b"; SameSite=None".decode('utf-8'),
    b"; Max-Age=999999; Expires=Thu, 01 Jan 2099 00:00:00 GMT".decode('utf-8'),
    b"foo\r\nSet-Cookie: admin=true".decode('utf-8'),
    b";\tPath\t=\t/".decode('utf-8'),
    b"; SECURE;  HTTPONLY".decode('utf-8'),
    b"val; Domain=.attacker.com; Path=/; SameSite=None; Secure".decode('utf-8'),
    b"normal;Max-Age=0\r\nX-Injected:true".decode('utf-8'),
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_cookie_injection_hr_portal_payroll_operations_py_105"
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