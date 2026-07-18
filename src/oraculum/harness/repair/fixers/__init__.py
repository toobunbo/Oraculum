from oraculum.harness.repair.fixers.seed_encoding import fix_seed_encoding
from oraculum.harness.repair.fixers.framework_context import fix_framework_context
from oraculum.harness.repair.fixers.llm_agent import fix_with_llm
from oraculum.harness.repair.fixers.atheris_timeout import fix_atheris_timeout

FIXER_REGISTRY = {
    "seed_encode": fix_seed_encoding,
    "django_setup": fix_framework_context,
    "flask_context": fix_framework_context,
    "fastapi_setup": fix_framework_context,
    "import_error": fix_with_llm,
    "oracle_type": fix_with_llm,
    "atheris_crash": fix_with_llm,
    "atheris_timeout": fix_atheris_timeout,
    "unknown": fix_with_llm,
}

_current_error = ""

def set_current_error(stderr: str) -> None:
    global _current_error
    _current_error = stderr

def get_current_error() -> str:
    return _current_error

__all__ = ["FIXER_REGISTRY", "fix_seed_encoding", "fix_framework_context", "fix_with_llm",
           "fix_atheris_timeout", "set_current_error", "get_current_error"]
