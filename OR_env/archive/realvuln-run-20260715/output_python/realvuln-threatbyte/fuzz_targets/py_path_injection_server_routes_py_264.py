import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock
from io import BytesIO

REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-threatbyte"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():
    from server.routes import upload_file
    from server import app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("\\.\\./", re.IGNORECASE),

    re.compile("\\.\\.\\\\", re.IGNORECASE),

    re.compile("/etc/", re.IGNORECASE),

    re.compile("\\\\etc\\\\", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_PATH_INJECTION: path traversal detected in file.save argument — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "file", "index": 0, "type": "FileStorage"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : server.routes.file.save
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def upload_file()
# condition        : The captured filepath contains directory traversal sequences (../) that would escape the intended upload directory
# capture_what     : filepath argument passed to file.save() containing path traversal sequences derived from unsanitized filename
# skip_hint        : False
# ========================================


_SEED_CORPUS = [
    b"../../../etc/passwd",
    b"..\\..\\..\\windows\\system32\\config\\sam",
    b"....//....//....//etc//passwd",
    b"..%2f..%2f..%2fetc%2fshadow",
    b"..././..././..././etc/hosts",
    b"..%252f..%252f..%252fetc%252fpasswd",
    b"/etc/passwd",
    b"..\\./..\\./..\\./etc/passwd",
    b"....\\\\....\\\\....\\\\etc\\\\passwd",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    param_file = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')

    with app.test_request_context(
        method='POST',
        data={'file': (BytesIO(b"fake_content"), param_file)},
        content_type='multipart/form-data'
    ):
        with patch('server.routes.file.save') as mock_save:
            try:
                upload_file()
            except RuntimeError:
                raise
            except Exception:
                pass

            for call in mock_save.call_args_list:
                captured = None
                if call.args and len(call.args) > 0:
                    captured = str(call.args[0])
                if captured is None:
                    continue
                for pattern in _COMPILED_PATTERNS:
                    match = pattern.search(captured)
                    if match:
                        raise RuntimeError(_RAISE_MESSAGE.format(
                            captured=captured,
                            matched_pattern=match.group()
                        ))


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-threatbyte/fuzz_corpus/py_path_injection_server_routes_py_264"
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