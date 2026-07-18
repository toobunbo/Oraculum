import atheris
import sys
import re
import os

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-healthcare-clinic-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from django.http import HttpRequest

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "clinic_portal.settings")
django.setup()

with atheris.instrument_imports():
    from clinic_portal.patient_operations import patient_crumb_lane_297


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(";\\s*HttpOnly", re.IGNORECASE),

    re.compile(";\\s*Secure", re.IGNORECASE),

    re.compile(";\\s*Domain\\s*=", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COOKIE_INJECTION: cookie attribute injection detected in response cookies — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def patient_crumb_lane_297(request)
# condition        : The string representation of the response's SimpleCookie contains injected cookie attributes (HttpOnly, Secure, Domain) that were not explicitly set by set_cookie(), confirming cookie attribute injection via the unsanitized marker value.
# capture_what     : string representation of response.cookies via str(return_value.cookies)
# skip_hint        : False
# ========================================


# === RETURN_VALUE SKELETON ===
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    if len(data) < 2:
        return

    key_size = min(16, max(0, len(data) - 1))
    key_bytes = fdp.ConsumeBytes(key_size)
    remaining = len(data) - key_size
    value_bytes = fdp.ConsumeBytes(remaining) if remaining > 0 else b""

    key = key_bytes.decode('utf-8', errors='ignore')
    key = re.sub(r'[^a-zA-Z0-9_]', '', key)

    value = value_bytes.decode('utf-8', errors='ignore')

    request = HttpRequest()

    if key:
        request.COOKIES[key] = value

    for fallback_key in ['crumb', 'patient_crumb', 'lane']:
        request.COOKIES[fallback_key] = value

    request.META['HTTP_COOKIE'] = "crumb=" + value

    try:
        response = patient_crumb_lane_297(request)
    except RuntimeError:
        raise
    except Exception:
        return

    if response is None:
        return

    captured = str(response.cookies)
    if not isinstance(captured, str):
        return

    for pattern in _COMPILED_PATTERNS:
        m = pattern.search(captured)
        if m:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.group()))
# ==========================================


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value; HttpOnly",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value;  Secure",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value;Domain=evil.com",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value;HTTPONLY",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value;\tSecure",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value\n; HttpOnly",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value; Secure; Domain=.evil.com",
    "patient_crumb\x00\x00\x00value; HttpOnly",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00value;  SECURE",
    "crumb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00x;Domain=.attacker.com; HttpOnly",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-healthcare-clinic-django/fuzz_corpus/py_cookie_injection_clinic_portal_patient_operations_py_96"
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