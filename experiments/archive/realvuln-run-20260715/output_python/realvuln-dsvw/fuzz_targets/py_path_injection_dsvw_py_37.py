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


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [
    re.compile(r"\.\./", re.IGNORECASE),
    re.compile(r"\.\.\\", re.IGNORECASE),
    re.compile(r"^\/etc\/passwd", re.IGNORECASE),
]
_RAISE_MESSAGE  = "PY_PATH-INJECTION: Path traversal detected - captured={captured} pattern={matched_pattern}"
# ========================================

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    param_path = fdp.ConsumeBytes(1024).decode('utf-8', errors='ignore')
    if not param_path.strip():
        return
    with patch('builtins.open', MagicMock()) as mock_open:
        try:
            handler = _target_mod.ReqHandler()
            handler.path = '/?path=' + param_path
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


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
# LLM: populate _SEED_CORPUS with entries designed to SURVIVE the filter,
# not just trigger it. Cover: mixed case, whitespace injection, unicode
# homoglyphs, double encoding, tag nesting, attribute abuse.
_SEED_CORPUS = [
    "../etc/passwd",
    "..\\windows\\win.ini",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "%2e%2e%2fetc%2fpasswd",
    "..\\/etc/passwd",
    "\\\\?\\C:\\windows\\win.ini",
    "....//etc/passwd"
]


if __name__ == "__main__":
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "/home/trieudai/Oraculum/output/python/realvuln-dsvw/fuzz_corpus/py_path_injection_dsvw_py_37"
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