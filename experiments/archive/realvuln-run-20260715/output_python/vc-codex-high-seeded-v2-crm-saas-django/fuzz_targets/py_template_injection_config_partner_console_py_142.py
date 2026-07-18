import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/vc-codex-high-seeded-v2-crm-saas-django"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from config.partner_console import acct_jinja_cast_585


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\{\\{.+?\\}\\}", re.IGNORECASE),

    re.compile("\\{%.+?%\\}", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_TEMPLATE_INJECTION: SSTI detected in Template() source — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "request", "index": 0, "type": "HttpRequest"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : config.partner_console.Template
# target_arg_index : 0
# target_arg_name  : source
# input_strategy   : direct_params
# signature        : def acct_jinja_cast_585(request)
# condition        : The captured template-source string contains Jinja2 expression delimiters ({{ or {%) that originate from user-controlled fragment input, confirming SSTI
# capture_what     : Template-source string passed to Jinja2 Template constructor, which is 'Result: ' + fragment
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"{{config}}",
    b"{% if 1 %}yes{% endif %}",
    b"{{7*7}}",
    b"{%import os%}",
    b"{{ ''.__class__.__mro__ }}",
    b"{{request.application.__globals__}}",
    b"{{Config}}",
    b"{%  if 1  %}x{%  endif  %}",
    b"{{lipsum.__globals__}}",
    b"{% for x in ().__class__.__bases__ %}{{x}}{% endfor %}",
    b"{{cycler.__init__.__globals__}}",
    b"{% set x = ''.__class__ %}{{x}}",
]



def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    fragment = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    mock_request = MagicMock()
    mock_request.GET = {'fragment': fragment}
    mock_request.POST = {'fragment': fragment}
    mock_request.data = {'fragment': fragment}
    mock_request.body = fragment.encode('utf-8', errors='ignore')
    mock_request.method = 'POST'

    with patch('config.partner_console.Template') as mock_template:
        mock_template.return_value = MagicMock()

        try:
            acct_jinja_cast_585(mock_request)
        except RuntimeError:
            raise
        except Exception:
            pass

        for call in mock_template.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get('source', ''))

            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=match.group()))



if __name__ == "__main__":
    _CORPUS_DIR = "output/python/vc-codex-high-seeded-v2-crm-saas-django/fuzz_corpus/py_template_injection_config_partner_console_py_142"
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