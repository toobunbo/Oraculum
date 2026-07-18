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

    re.compile(";\\s*[a-zA-Z/]", re.IGNORECASE),

    re.compile("\\|\\s*[a-zA-Z/]", re.IGNORECASE),

    re.compile("&&\\s*[a-zA-Z/]", re.IGNORECASE),

    re.compile("\\$\\(", re.IGNORECASE),

    re.compile("`[^`]+`", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_SHELL_COMMAND_CONSTRUCTED_FROM_INPUT: command injection detected in helpers.run_cmd argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "host", "index": 1, "type": "str"}, {"name": "port", "index": 2, "type": "str"}, {"name": "path", "index": 3, "type": "str"}, {"name": "scheme", "index": 4, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : helpers.run_cmd
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def mutate(info, host, port, path, scheme)
# condition        : The captured command string contains shell metacharacters (semicolons, pipes, logical AND, command substitution via $() or backticks) embedded after the URL portion, indicating a command injection payload broke through strip_dangerous_characters.
# capture_what     : The full shell command string passed to helpers.run_cmd, containing the curl command with the user-controlled URL
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

_SEED_CORPUS = [
    b"127.0.0.1; cat /etc/passwd" + b"8080" + b"/" + b"http",
    b"localhost" + b"80| cat /etc/passwd" + b"/" + b"http",
    b"localhost" + b"80" + b"/api$(cat /etc/passwd)" + b"http",
    b"localhost" + b"80" + b"/" + b"http`cat /etc/passwd`",
    b"127.0.0.1&& cat /etc/passwd" + b"80" + b"/" + b"http",
    b"localhost" + b"8080" + b"/; ls -la /etc" + b"http",
    b"localhost" + b"8080; whoami" + b"/api" + b"http",
    b"127.0.0.1" + b"8080" + b"/test| whoami" + b"https",
    b"host; /bin/sh -c id" + b"443" + b"/graphql" + b"https",
    b"target" + b"80" + b"/query&& id" + b"http",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    n = len(data)
    chunk = n // 4

    host = fdp.ConsumeBytes(chunk).decode('utf-8', errors='ignore')
    port = fdp.ConsumeBytes(chunk).decode('utf-8', errors='ignore')
    path = fdp.ConsumeBytes(chunk).decode('utf-8', errors='ignore')
    scheme = fdp.ConsumeBytes(n - 3 * chunk).decode('utf-8', errors='ignore')

    info = MagicMock()

    with patch('helpers.run_cmd', return_value=MagicMock()) as mock_run_cmd:
        try:
            _target_mod.mutate(info, host, port, path, scheme)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_run_cmd.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            if captured is None:
                continue
            for pattern in _COMPILED_PATTERNS:
                m = pattern.search(captured)
                if m:
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-graphql-application/fuzz_corpus/py_shell_command_constructed_from_input_core_views_py_211"
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