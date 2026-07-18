import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()

with atheris.instrument_imports():

    from config.partner_console import acct_vault_stash_244


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\"ssn\"\\s*:\\s*\"\\d{3}-\\d{2}-\\d{4}\"", re.IGNORECASE),

    re.compile("\"card\"\\s*:\\s*\"\\d{13,19}\"", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CLEAR_TEXT_STORAGE_SENSITIVE_DATA: cleartext SSN or card number written to file — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.write_text
# target_arg_index : 0
# target_arg_name  : data
# input_strategy   : direct_params
# signature        : def acct_vault_stash_244(request)
# condition        : The captured JSON string contains cleartext SSN (format XXX-XX-XXXX) or credit card number (13-19 digits) as a JSON value, confirming sensitive data is stored without encryption
# capture_what     : JSON string passed to write_text containing cleartext SSN and credit card number
# skip_hint        : False
# ========================================


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b'{"ssn": "123-45-6789"}',
    b'{"card": "1234567890123456"}',
    b'{"SSN": "000-00-0000", "card": "1111222233334444"}',
    b'{"ssn"  :  "999-88-7777"}',
    b'{"CARD"  :  "5500000000000004"}',
    b'{"user": "test", "ssn": "333-22-1111", "card": "4111111111111111"}',
    b'{"ssn":"444-55-6666","name":"admin"}',
    b'{"card":"378282246310005","type":"amex"}',
    b'{"data":{"ssn": "666-77-8888"}}',
    b'{"profile":{"card": "6011111111111117"}}',
]



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # Generate the request body from all remaining fuzzed bytes
    raw_body = fdp.ConsumeBytes(len(data))

    # Create a mock Django HttpRequest with the fuzzed body
    mock_request = MagicMock()
    mock_request.body = raw_body
    mock_request.method = "POST"
    mock_request.content_type = "application/json"
    mock_request.META = {"CONTENT_TYPE": "application/json"}
    mock_request.GET = {}
    mock_request.POST = {}
    mock_request.FILES = {}
    mock_request.COOKIES = {}
    mock_request.session = {}

    # Mock the sink: pathlib.Path.write_text
    with patch("pathlib.Path.write_text") as mock_write_text:
        try:
            acct_vault_stash_244(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        # Oracle check — OUTSIDE the function call try/except, INSIDE patch context
        for call in mock_write_text.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif "data" in call.kwargs:
                captured = str(call.kwargs["data"])

            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured)
                    if match:
                        raise RuntimeError(
                            _RAISE_MESSAGE.format(
                                captured=captured,
                                matched_pattern=match.group()
                            )
                        )


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_clear_text_storage_sensitive_data_config_partner_console_py_92"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed if isinstance(_seed, bytes) else _seed.encode("utf-8"))

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()