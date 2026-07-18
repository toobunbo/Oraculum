import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-pythonssti"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from main import read_root


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\{\\{.*?\\}\\}", re.IGNORECASE),

    re.compile("\\{%.*?%\\}", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_TEMPLATE_INJECTION: SSTI payload detected in template source — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "username", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : main.Jinja2.from_string
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def read_root(username)
# condition        : The captured template-source string contains Jinja2 expression delimiters ({{ or {%}) indicating user-controlled data was injected as template syntax rather than being passed as a safe variable.
# capture_what     : template-source string argument passed to Jinja2.from_string, which contains the user-controlled username concatenated into 'Welcome ' + username + '!'
# skip_hint        : not username
# ========================================


_SEED_CORPUS = [
    b"{{config}}",
    b"{%import os%}",
    b"{{7*7}}",
    b"{% if 1 %}yes{% endif %}",
    b"{{request.application.__globals__}}",
    b"{% for x in [1] %}{{x}}{% endfor %}",
    b"{{Config.__class__.__init__.__globals__}}",
    b"{% set x = 1 %}{{x}}{% endset %}",
    b"{{ ''.__class__.__mro__[1].__subclasses__() }}",
    b"{%import subprocess%}{%subprocess.call('id',shell=True)%}",
    b"{{ lipsum.__globals__['os'].popen('id').read() }}",
    b"{%config.__class__.__init__.__globals__['os'].popen('cat /etc/passwd').read()%}",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    username = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    if not username:
        return

    with patch('main.Jinja2.from_string', return_value=MagicMock()) as mock_from_string:
        try:
            read_root(username)
        except Exception:
            pass

        for call in mock_from_string.call_args_list:
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
    _CORPUS_DIR = "output/python/realvuln-pythonssti/fuzz_corpus/py_template_injection_main_py_14"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed)

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()