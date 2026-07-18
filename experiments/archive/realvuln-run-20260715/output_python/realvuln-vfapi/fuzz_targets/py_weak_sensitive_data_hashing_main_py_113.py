# AUTO-GENERATED ATHERIS HARNESS
# rule_id  : py/weak-sensitive-data-hashing
# function : init_sql_db
# file     : main.py
# ================================================================
import atheris
import sys
import re
import os

from unittest.mock import patch, MagicMock



REPO_ROOT = "/home/trieudai/VulnHunterX/repos/python/realvuln-vfapi"
if REPO_ROOT and REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

with atheris.instrument_imports():

    from main import init_sql_db, app


# === FIXED CONTRACTS (DO NOT MODIFY) ===
_COMPILED_PATTERNS = [

    re.compile("INSERT\\s+INTO\\s+users.*?'[0-9a-f]{32}'", re.IGNORECASE),

    re.compile("'[0-9a-f]{32}'", re.IGNORECASE),

]
_RAISE_MESSAGE  = "PY_WEAK_SENSITIVE_DATA_HASHING: password hashed with unsalted MD5 detected in SQL INSERT — captured={captured} pattern={matched_pattern}"
_TAINTED_PARAMS = []
# ========================================

# === ORACLE CONTEXT ===
# strategy         : recorded_call
# patch_target     : sqlite3.Cursor.execute
# target_arg_index : 0
# target_arg_name  : None
# input_strategy   : flask_view
# signature        : def init_sql_db()
# condition        : The captured SQL query string contains an INSERT INTO users statement with a password value that is an unsalted MD5 hex digest (exactly 32 lowercase hex characters enclosed in SQL string quotes)
# capture_what     : SQL query string passed to cursor.execute containing the MD5-hashed password value
# skip_hint        : False
# ========================================


# === SEED CORPUS — bypass-oriented, derived from trigger_patterns ===
_SEED_CORPUS = [
    b"password=5f4dcc3b5aa765d61d8327deb882cf99",
    b"admin_password=e10adc3949ba59abbe56e057f20f883e",
    b"DEFAULT_PASSWORD=21232f297a57a5a743894a0e4a801fc3",
    b"password=098f6bcd4621d373cade4e832627b4f6&role=admin",
    b"secret=d41d8cd98f00b204e9800998ecf8427e",
    b"hash=c4ca4238a0b923820dcc509a6f75849b&user=root",
    b"pwd=7c6a61c68ef8b9b6b061b28c348bc1ed",
    b"pass=670b14728ad9902aecba32e22fa4f6bd&username=admin",
]


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    # 1. Generate inputs from fdp — consume all bytes as raw query string
    raw = fdp.ConsumeBytes(len(data))
    query_string = raw.decode('utf-8', errors='ignore')

    # 2. Wrap in Flask Request Context
    with app.test_request_context(query_string=query_string):
        # 3. Mock the patch target
        with patch('sqlite3.Cursor.execute') as mock_execute:
            mock_execute.return_value = MagicMock()

            # 4. Call target function inside the mock context
            try:
                init_sql_db()
            except Exception:
                pass

            # 5. Oracle check — OUTSIDE the function call try/except, INSIDE patch context
            for call in mock_execute.call_args_list:
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
    # Export seed corpus to disk so libFuzzer can mutate raw bytes directly.
    # This preserves coverage-guided mutation — fuzzer mutates content, not index.
    _CORPUS_DIR = "output/python/realvuln-vfapi/fuzz_corpus/py_weak_sensitive_data_hashing_main_py_113"
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