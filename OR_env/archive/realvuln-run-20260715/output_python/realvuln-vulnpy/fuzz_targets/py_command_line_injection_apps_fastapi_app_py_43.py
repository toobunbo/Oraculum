import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnpy"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from apps.fastapi_app import cmdi


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile(";\\s*\\w+", re.IGNORECASE),

    re.compile("&&\\s*\\w+", re.IGNORECASE),

    re.compile("\\|\\|\\s*\\w+", re.IGNORECASE),

    re.compile("\\$\\(", re.IGNORECASE),

    re.compile("`[^`]+`", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COMMAND-LINE-INJECTION: shell metacharacter injection in os.system argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "user_input", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : apps.fastapi_app.os.system
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def cmdi(user_input: str)
# condition        : The captured command string contains shell metacharacters that break out of the echo context, confirming command injection via unsanitized user_input concatenation
# capture_what     : full command string passed to os.system, constructed as 'echo ' + user_input + ' this should be echoed'
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"; id",
    b"&& whoami",
    b"|| cat /etc/passwd",
    b"$(id)",
    b"`id`",
    b";  ID",
    b"&&\twhoami",
    b"||\nls",
    b"$(whoami)",
    b"`cat /etc/shadow`",
    b";Id",
    b"&&WHOAMI",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    user_input = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    with patch('apps.fastapi_app.os.system') as mock_system:
        mock_system.return_value = MagicMock()

        try:
            cmdi(user_input)
        except Exception:
            pass

        for call in mock_system.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            if captured is None:
                continue
            for pattern in _COMPILED_PATTERNS:
                match = pattern.search(captured)
                if match:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.group()))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-vulnpy/fuzz_corpus/py_command_line_injection_apps_fastapi_app_py_43"
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