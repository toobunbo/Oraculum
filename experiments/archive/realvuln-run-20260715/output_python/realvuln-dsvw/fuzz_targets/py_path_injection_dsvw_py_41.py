import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-dsvw"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    import dsvw as _target_mod


# === RECORDED_CALL: patch open() to detect path traversal ===
_COMPILED_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"~", re.IGNORECASE),
]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: path traversal detected — captured={captured} pattern={matched_pattern}"

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    path_input = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    if not path_input.strip():
        return
    with patch('builtins.open', MagicMock()) as mock_open:
        try:
            handler = _target_mod.ReqHandler()
            handler.path = '/?' + path_input
            handler.wfile = MagicMock()
            handler.headers = {}
            handler.do_GET()
        except RuntimeError:
            raise
        except Exception:
            pass
        for call in mock_open.call_args_list:
            captured = str(call.args[0]) if call.args else ""
            for pattern in _COMPILED_PATTERNS:
                if pattern.search(captured):
                    raise RuntimeError(_RAISE_MESSAGE.format(captured=captured, matched_pattern=pattern.pattern))


_SEED_CORPUS = [
    "/?path=../../../etc/passwd",
    "/?path=..\\..\\..\\windows\\system.ini",
    "/?path=~/../.ssh/id_rsa",
    "/?path=....//....//....//etc/shadow",
    "/?path=..%252f..%252f..%252fetc%252fpasswd",
    "/?path=../etc/passwd%00",
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_41"
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