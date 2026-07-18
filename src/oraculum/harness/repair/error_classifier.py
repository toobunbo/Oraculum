import re
from enum import Enum


class ErrorType(Enum):
    SEED_ENCODE = "seed_encode"
    DJANGO_SETUP = "django_setup"
    FLASK_CONTEXT = "flask_context"
    FASTAPI_SETUP = "fastapi_setup"
    IMPORT_ERROR = "import_error"
    ORACLE_TYPE = "oracle_type_guard"
    ATHERIS_CRASH = "atheris_crash"
    ATHERIS_TIMEOUT = "atheris_timeout"
    UNKNOWN = "unknown"

    @property
    def description(self) -> str:
        return {
            ErrorType.SEED_ENCODE: "_seed.encode() on bytes literal",
            ErrorType.DJANGO_SETUP: "Django settings not configured",
            ErrorType.FLASK_CONTEXT: "Flask request context missing",
            ErrorType.FASTAPI_SETUP: "FastAPI TestClient not set up",
            ErrorType.IMPORT_ERROR: "Module/function import failed",
            ErrorType.ORACLE_TYPE: "Oracle check type error (args/kwargs)",
            ErrorType.ATHERIS_CRASH: "Atheris instrumentation crash",
            ErrorType.ATHERIS_TIMEOUT: "Atheris instrumentation timeout",
            ErrorType.UNKNOWN: "Unrecognized error",
        }[self]


_ERROR_PATTERNS: list[tuple[re.Pattern, ErrorType]] = [
    (re.compile(r"'bytes'.*has no attribute 'encode'"), ErrorType.SEED_ENCODE),
    (re.compile(r"ImproperlyConfigured.*settings are not configured"), ErrorType.DJANGO_SETUP),
    (re.compile(r"Working outside of request context"), ErrorType.FLASK_CONTEXT),
    (re.compile(r"RuntimeError.*not a valid", re.IGNORECASE), ErrorType.FASTAPI_SETUP),
    (re.compile(r"does not support.*TestClient", re.IGNORECASE), ErrorType.FASTAPI_SETUP),
    (re.compile(r"ModuleNotFoundError"), ErrorType.IMPORT_ERROR),
    (re.compile(r"ImportError"), ErrorType.IMPORT_ERROR),
    (re.compile(r"IndexError.*tuple index out of range"), ErrorType.ORACLE_TYPE),
    (re.compile(r"KeyError.*args"), ErrorType.ORACLE_TYPE),
    (re.compile(r"TypeError.*NoneType"), ErrorType.ORACLE_TYPE),
    (re.compile(r"SystemError"), ErrorType.ATHERIS_CRASH),
    (re.compile(r"Segmentation fault"), ErrorType.ATHERIS_CRASH),
    (re.compile(r"TIMEOUT"), ErrorType.ATHERIS_TIMEOUT),
]


def classify_error(stderr: str) -> ErrorType:
    if not stderr:
        return ErrorType.UNKNOWN

    last_tb = stderr.split("Traceback (most recent call last)")[-1]

    for pattern, error_type in _ERROR_PATTERNS:
        if pattern.search(last_tb):
            return error_type

    return ErrorType.UNKNOWN
