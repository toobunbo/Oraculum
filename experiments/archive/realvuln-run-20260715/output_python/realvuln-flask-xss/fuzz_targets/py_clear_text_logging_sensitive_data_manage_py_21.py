import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-flask-xss"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from manage import add_admin


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("(?i)password[^a-zA-Z]*\\S{4,}", re.IGNORECASE),

    re.compile("(?i)pass\\s*[:=]\\s*\\S{4,}", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_CLEAR_TEXT_LOGGING_SENSITIVE_DATA: cleartext password logged — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = [{"name": "password", "index": 0, "type": "str"}]
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : manage.app.logger.info
# target_arg_index : 0
# target_arg_name  : msg
# input_strategy   : direct_params
# signature        : def add_admin(password)
# condition        : The captured log message argument contains the keyword 'password' (case-insensitive) followed by non-whitespace characters, indicating the actual password value is being logged in cleartext rather than masked or hashed
# capture_what     : log message string containing the cleartext password passed to app.logger.info on line 21
# skip_hint        : not password
# ========================================


_SEED_CORPUS = [
    b"SuperSecret123!",
    b"admin_P@ssw0rd",
    b"s3cr3tK3y#2024",
    b"MyP@ss:hardtocrack",
    b"pass=Chang3MeNow!",
    b"PASSWORD_override99",
    b"test1234pass",
    b"p4ssw0rd!@#$%",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    password = fdp.ConsumeBytes(len(data)).decode("utf-8", errors="ignore")

    if not password:
        return

    with patch("manage.app.logger.info", MagicMock()) as mock_logger_info:
        try:
            add_admin(password)
        except Exception:
            pass

        for call in mock_logger_info.call_args_list:
            captured = None
            if call.args and len(call.args) > 0:
                captured = str(call.args[0])
            elif call.kwargs:
                captured = str(call.kwargs.get("msg", ""))

            if captured is None:
                continue

            for pattern in _COMPILED_PATTERNS:
                match = pattern.search(captured)
                if match:
                    raise RuntimeError(
                        _RAISE_MESSAGE.format(
                            captured=captured,
                            matched_pattern=match.pattern,
                        )
                    )


if __name__ == "__main__":
    _CORPUS_DIR = "output/python/realvuln-flask-xss/fuzz_corpus/py_clear_text_logging_sensitive_data_manage_py_21"
    os.makedirs(_CORPUS_DIR, exist_ok=True)
    for _i, _seed in enumerate(_SEED_CORPUS):
        _seed_path = os.path.join(_CORPUS_DIR, f"seed_{_i:03d}")
        if not os.path.exists(_seed_path):
            with open(_seed_path, "wb") as _f:
                _f.write(_seed.encode("utf-8") if isinstance(_seed, str) else _seed)

    if _CORPUS_DIR not in sys.argv:
        sys.argv.append(_CORPUS_DIR)

    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()