import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-healthcare-clinic-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "clinic_portal.settings")
django.setup()

with atheris.instrument_imports():

    from clinic_portal.patient_operations import patient_xml_fold_453


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!DOCTYPE[\\s\\S]*?<!ENTITY[\\s\\S]*?SYSTEM", re.IGNORECASE),

    re.compile("<!DOCTYPE[\\s\\S]*?<!ENTITY[\\s\\S]*?PUBLIC", re.IGNORECASE),

    re.compile("<!ENTITY\\s+%\\s+\\S+\\s+SYSTEM", re.IGNORECASE),

    re.compile("SYSTEM\\s+[\"']file://", re.IGNORECASE),

    re.compile("SYSTEM\\s+[\"']http", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_XXE: XXE payload detected in etree.fromstring — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : clinic_portal.patient_operations.etree.fromstring
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def patient_xml_fold_453(request)
# condition        : The captured XML payload contains a DOCTYPE declaration with an ENTITY definition using SYSTEM or PUBLIC to reference external resources, indicating XXE exploitation
# capture_what     : XML bytes/string passed to etree.fromstring from request.body
# skip_hint        : len(request.body) < 15
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


_SEED_CORPUS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "foo" "file:///etc/hostname">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "file:///etc/passwd">%dtd;]><foo>test</foo>',
    '<?XML VERSION="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "FILE:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE  foo  [  <!ENTITY  xxe  SYSTEM  "http://localhost/admin"  >  ]  ><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo[<!ENTITY xxe SYSTEM"http://127.0.0.1">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/shadow">%xxe;]><root/>',
    '<?xml version="1.0"?>\n<!DOCTYPE doc [\n<!ENTITY xxe SYSTEM "http://10.0.0.1/secrets">\n]>\n<doc>&xxe;</doc>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY ext PUBLIC "-//Example//DTD//EN" "http://metadata.google.internal/">]><data>&ext;</data>',
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # 1. INPUT GENERATION — consume all remaining bytes as request body
    body_bytes = fdp.ConsumeBytes(len(data))

    # 2. SKIP CONDITION — based on skip_hint, applied to input only
    if len(body_bytes) < 15:
        return

    # Build a mock HttpRequest with the fuzzed body
    mock_request = MagicMock()
    mock_request.body = body_bytes

    # 3. MOCK SETUP — patch only the sink
    with patch("clinic_portal.patient_operations.etree.fromstring") as mock_fromstring:
        mock_fromstring.return_value = MagicMock()

        # 4. FUNCTION CALL — inside patch context, swallow non- RuntimeError
        try:
            patient_xml_fold_453(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        # 5. ORACLE CHECK — OUTSIDE function try/except, INSIDE patch context
        for call in mock_fromstring.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]
            elif call.kwargs:
                captured = call.kwargs.get("text")

            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    matched = pattern.search(captured_str)
                    if matched:
                        raise RuntimeError(
                            _RAISE_MESSAGE.format(
                                captured=captured_str,
                                matched_pattern=pattern.pattern,
                            )
                        )

    # 6. EXCEPTION HANDLING — RuntimeError already raised above, nothing else to do


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-healthcare-clinic-django/fuzz_corpus/py_xxe_clinic_portal_patient_operations_py_188"
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