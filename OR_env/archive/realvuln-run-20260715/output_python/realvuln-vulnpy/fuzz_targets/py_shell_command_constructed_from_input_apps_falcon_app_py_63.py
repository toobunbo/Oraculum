import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vulnpy"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from apps.falcon_app import thread_function


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("echo .+; .+", re.IGNORECASE),

    re.compile("echo .+&& .+", re.IGNORECASE),

    re.compile("echo .+\\|\\| .+", re.IGNORECASE),

    re.compile("echo .+\\| .+", re.IGNORECASE),

    re.compile("echo .+\\$\\(.+\\)", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY/SHELL-COMMAND-CONSTRUCTED-FROM-INPUT: shell injection detected in os.system arg — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "user_input", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : os.system
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def thread_function(user_input)
# condition        : The captured command string starts with 'echo ' and contains shell metacharacters (;, &&, ||, |, $()) that indicate command injection
# capture_what     : The full command string passed to os.system, constructed as 'echo ' + str(user_input)
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"test; ls",
    b"test&& whoami",
    b"test|| cat /etc/passwd",
    b"test| id",
    b"test$(whoami)",
    b"hello; rm -rf /",
    b" ; ls",
    b"a&b;ls",
    b"TEST; LS",
    b"test\n; ls",
    b"test\t&& whoami",
    b"x$(cat /etc/shadow)y",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    user_input = fdp.ConsumeBytes(len(data)).decode("utf-8", errors="ignore")

    with patch("os.system", MagicMock(return_value=0)) as mock_system:
        try:
            thread_function(user_input)
        except Exception:
            pass

        for call in mock_system.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured)
                    if m:
                        raise RuntimeError(
                            _RAISE_MESSAGE.format(
                                captured=captured,
                                matched_pattern=m.pattern.pattern,
                            )
                        )


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-vulnpy/fuzz_corpus/py_shell_command_constructed_from_input_apps_falcon_app_py_63"
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