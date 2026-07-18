import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-claude-code-seeded-v2-hr-payroll-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from hr_portal.payroll_operations import payroll_shell_probe_402


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("ping -c 1 .*;.*", re.IGNORECASE),

    re.compile("ping -c 1 .*&&.*", re.IGNORECASE),

    re.compile("ping -c 1 .*\\|.*", re.IGNORECASE),

    re.compile("ping -c 1 .*\\$\\(.*\\)", re.IGNORECASE),

    re.compile("ping -c 1 .*`.*`", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COMMAND-LINE-INJECTION: shell injection in os.system command — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "object"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : hr_portal.payroll_operations._os.system
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def payroll_shell_probe_402(request)
# condition        : The captured command string contains 'ping -c 1 ' followed by a shell metacharacter (;, &&, |, $() or backtick) that introduces an injected command
# capture_what     : the full command string passed to _os.system, which is 'ping -c 1 ' concatenated with the user-controlled host value
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    "127.0.0.1;cat /etc/passwd",
    "127.0.0.1&&whoami",
    "192.168.1.1|ls -la /",
    "10.0.0.1$(id)",
    "localhost`uname -a`",
    "127.0.0.1 ; cat /etc/shadow",
    "8.8.8.8\t;id",
    "127.0.0.1;echo YmFzaA==|base64 -d|bash",
]



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    payload = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    request_mock = MagicMock()

    get_dict = MagicMock()
    get_dict.get.return_value = payload
    get_dict.__getitem__.return_value = payload
    request_mock.GET = get_dict

    post_dict = MagicMock()
    post_dict.get.return_value = payload
    post_dict.__getitem__.return_value = payload
    request_mock.POST = post_dict

    with patch('hr_portal.payroll_operations._os.system') as mock_system:
        mock_system.return_value = 0

        try:
            payroll_shell_probe_402(request_mock)
        except RuntimeError:
            raise
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
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern.pattern))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-claude-code-seeded-v2-hr-payroll-django/fuzz_corpus/py_command_line_injection_hr_portal_payroll_operations_py_156"
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