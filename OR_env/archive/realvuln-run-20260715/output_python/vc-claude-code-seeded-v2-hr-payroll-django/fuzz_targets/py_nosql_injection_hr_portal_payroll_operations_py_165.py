import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "hr_portal.settings")
django.setup()

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_mongo_lane_413


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("'\\$where'", re.IGNORECASE),

    re.compile("\"\\$where\"", re.IGNORECASE),

    re.compile("'\\$gt'", re.IGNORECASE),

    re.compile("\"\\$gt\"", re.IGNORECASE),

    re.compile("'\\$ne'", re.IGNORECASE),

    re.compile("\"\\$ne\"", re.IGNORECASE),

    re.compile("'\\$regex'", re.IGNORECASE),

    re.compile("\"\\$regex\"", re.IGNORECASE),

    re.compile("'\\$or'", re.IGNORECASE),

    re.compile("\"\\$or\"", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_NOSQL_INJECTION: NoSQL operator injected into find_one query — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pymongo.collection.Collection.find_one
# target_arg_index : 0
# target_arg_name  : filter
# input_strategy   : direct_params
# signature        : def payroll_mongo_lane_413(request)
# condition        : The captured query dict contains MongoDB operator keys such as $where, $gt, $ne, or $regex, indicating NoSQL injection of unsanitized user input
# capture_what     : query dict passed to find_one containing unsanitized user input with potential MongoDB operators
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===
# TODO: Complete TestOneInput following these steps:
# 1. Generate inputs using FuzzedDataProvider.
# 2. Apply skip_hint (if applicable).
# 3. Mock the patch target using patch/MagicMock.
# 4. Call target function inside the mock context.
# 5. Compare mock call arguments against _COMPILED_PATTERNS.
# 6. Propagate RuntimeError; swallow other exceptions.
# ==========================================



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.method = 'POST'
    mock_request.content_type = 'application/json'
    mock_request.body = payload.encode('utf-8', errors='ignore')
    mock_request.GET = {'q': payload, 'employee_id': payload, 'query': payload, 'id': payload}
    mock_request.POST = {'q': payload, 'employee_id': payload, 'query': payload, 'id': payload}
    mock_request.META = {'CONTENT_TYPE': 'application/json'}
    mock_request.COOKIES = {}
    mock_request.headers = {'Content-Type': 'application/json'}
    mock_request.data = payload
    mock_request._stream = None

    with patch('pymongo.collection.Collection.find_one', return_value=None) as mock_find:
        try:
            payroll_mongo_lane_413(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_find.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]
            elif 'filter' in call.kwargs:
                captured = call.kwargs['filter']

            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    if pattern.search(captured_str):
                        raise RuntimeError(_RAISE_MESSAGE.format(
                            captured=captured_str,
                            matched_pattern=pattern.pattern
                        ))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    b'{"$where": "1==1"}',
    b'{"$gt": ""}',
    b'{"$ne": null}',
    b'{"$regex": ".*"}',
    b'{"$or": [{"id": 1}]}',
    b'{"$WHERE": "true"}',
    b'{"$Where": "return true"}',
    b'{"$gt": "", "$ne": null}',
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_nosql_injection_hr_portal_payroll_operations_py_165"
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