import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-extremely-vulnerable-flask-app"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app import page_not_found


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\{\\{.*\\}\\}", re.IGNORECASE),

    re.compile("\\{%.*%\\}", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_TEMPLATE_INJECTION: SSTI payload detected in render_template_string source — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "error", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : flask.render_template_string
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : direct_params
# signature        : def page_not_found(error)
# condition        : The captured template source string contains Jinja2 expression delimiters ({{ or {%) indicating user-controlled SSTI payload reached the template engine
# capture_what     : Full template source string (f-string combining error and request.path) passed to render_template_string
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
    b"{{config}}",
    b"{{7*7}}",
    b"{% if 1==1 %}yes{% endif %}",
    b"{{ self.__init__.__globals__ }}",
    b"{%for x in ().__class__.__bases__[0].__subclasses__()%}{%endfor%}",
    b"{{ ''.__class__.__mro__[1].__subclasses__() }}",
    b"{{request.application.__globals__}}",
    b"{% set x = ''.join.__globals__ %}{{x}}",
    b"{{  ().__class__.__bases__[0].__subclasses__()[132]  }}",
    b"{% config.__class__.__init__.__globals__['os'].popen('id').read() %}",
    b"{{ lipsum.__globals__['os'].popen('cat /etc/passwd').read() }}",
    b"{{ cycler.__init__.__globals__.os.popen('whoami').read() }}",
    b"{{namespace.__init__.__globals__['os'].popen('id').read()}}",
    b"{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    error = fdp.ConsumeBytes(len(data)).decode("utf-8", errors="ignore")

    with patch("flask.render_template_string", MagicMock(return_value="")) as mock_render:
        try:
            page_not_found(error)
        except Exception:
            pass

        for call in mock_render.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif "source" in call.kwargs:
                captured = str(call.kwargs["source"])
            elif "template_name_or_list" in call.kwargs:
                captured = str(call.kwargs["template_name_or_list"])

            if captured is not None:
                for pattern in _COMPILED_PATTERNS:
                    m = pattern.search(captured)
                    if m:
                        raise RuntimeError(
                            _RAISE_MESSAGE.format(
                                captured=captured,
                                matched_pattern=m.pattern,
                            )
                        )



if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-extremely-vulnerable-flask-app/fuzz_corpus/py_template_injection_app_py_32"
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