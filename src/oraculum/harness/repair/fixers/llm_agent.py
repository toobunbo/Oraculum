import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)


def fix_with_llm(source: str, repo_root: str = "", **kwargs) -> str:
    """Use DeepSeek to dynamically repair a harness based on its runtime error."""
    from oraculum.llm.client import call_llm
    from oraculum.harness.repair.fixers import get_current_error

    error_message = get_current_error() or ""

    prompts_dir = _get_prompts_dir()
    try:
        system_prompt = (prompts_dir / "repair_agent.txt").read_text(encoding="utf-8")
    except OSError:
        system_prompt = _FALLBACK_SYSTEM_PROMPT

    user_prompt = f"Error:\n{error_message}\n\nRepo root:\n{repo_root}\n\nHarness code:\n{source}"

    model = _resolve_model()

    try:
        raw = call_llm(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            model=model,
            temperature=0.1,
            max_tokens=4096,
            timeout=60,
        )
    except Exception as exc:
        logger.warning("LLM repair call failed: %s", exc)
        return source

    code = _extract_code(raw)
    if not code or code.strip() == source.strip():
        return source
    return code


def _extract_code(text: str) -> str:
    m = re.search(r"```(?:python)?\n(.*?)```", text, re.DOTALL)
    return m.group(1).strip() if m else text.strip()


def _get_prompts_dir() -> Path:
    _root = Path(__file__).parent.parent.parent.parent.parent
    return _root / "config" / "prompts"


def _resolve_model() -> str:
    provider = os.environ.get("LLM_PROVIDER", "openai")
    model = os.environ.get("LLM_MODEL", "deepseek-chat")
    return f"{provider}/{model}"


_FALLBACK_SYSTEM_PROMPT = """You are a Python repair agent. Fix the Python fuzz harness that failed with the given error.
The harness generates Atheris fuzz targets for vulnerable Python code.
Return ONLY the fixed Python code, no explanation.
Preserve all existing imports, FIXED CONTRACTS, and ORACLE CONTEXT sections.
Fix import paths, add try/except guards as needed.
For Django errors: add django.setup(). For Flask: use test_request_context(). For FastAPI: use TestClient."""
