import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-damn-vulnerable-graphql-application"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    import core.views as _target_mod


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("ps\\s+\\S+;\\s*\\S+", re.IGNORECASE),

    re.compile("ps\\s+\\S+&&\\s*\\S+", re.IGNORECASE),

    re.compile("ps\\s+\\S+\\|\\s*\\S+", re.IGNORECASE),

    re.compile("ps\\s+.*\\$\\(", re.IGNORECASE),

    re.compile("ps\\s+.*\\x60[^\\x60]+\\x60", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SHELL_COMMAND_CONSTRUCTED_FROM_INPUT: command injection detected — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "arg", "index": 1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : helpers.run_cmd
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def resolve_system_debug(info, arg)
# condition        : The captured command string contains shell metacharacters (;, &&, |, $(), backticks) after 'ps', indicating command injection via the tainted arg parameter
# capture_what     : shell command string passed to helpers.run_cmd
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"aux; cat /etc/passwd",
    b"aux&& whoami",
    b"aux| id",
    b"aux$(whoami)",
    b"aux`id`",
    b"-ef ; ls -la /",
    b"aux  ;  cat /etc/shadow",
    b"Aux; CAT /etc/hosts",
    b"aux\n;uname -a",
    b"aux;cat</etc/passwd",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    
    arg = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    mock_info = MagicMock()

    with patch('helpers.run_cmd', MagicMock()) as mock_run_cmd:
        try:
            _target_mod.resolve_system_debug(mock_info, arg)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_run_cmd.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = call.args[0]
            elif call.kwargs:
                captured = call.kwargs.get("cmd") or call.kwargs.get("command") or call.kwargs.get("args")

            if captured is not None:
                captured_str = str(captured)
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured_str)
                    if m:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured_str, matched_pattern=m.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-graphql-application/fuzz_corpus/py_shell_command_constructed_from_input_core_views_py_352"
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