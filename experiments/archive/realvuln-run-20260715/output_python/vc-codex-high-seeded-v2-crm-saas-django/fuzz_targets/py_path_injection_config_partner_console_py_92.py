import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock


import pathlib


REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from config.partner_console import acct_vault_stash_244


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.{2}/", re.IGNORECASE),

    re.compile("\\.{2}\\\\", re.IGNORECASE),

    re.compile("/etc/", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: path traversal detected in write_text target — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "ref", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : pathlib.Path.write_text
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_vault_stash_244(request)
# condition        : The string representation of the Path object contains directory traversal sequences (../ or ..\) or targets sensitive system directories via the ref-derived path segment
# capture_what     : Path object (self) whose str() contains the user-controlled ref interpolated into the file path
# skip_hint        : False
# ========================================


# === RECORDED_CALL SKELETON ===


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    ref_val = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    request = MagicMock()
    request.ref = ref_val

    with patch('pathlib.Path.write_text', return_value=MagicMock()) as mock_write:
        try:
            acct_vault_stash_244(request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_write.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    "../../../etc/passwd",
    "..\\..\\..\\etc\\hosts",
    "....//....//etc//shadow",
    "/etc/hosts",
    "..%2f..%2fetc%2fshadow",
    "....\\\\....\\\\etc\\\\passwd",
    "../ETC/PASSWD",
    "..\\..\\..\\Windows\\System32\\config\\SAM",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_path_injection_config_partner_console_py_92"
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