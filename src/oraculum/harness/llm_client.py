import ast
import re
from pathlib import Path

from oraculum.llm.client import call_llm as _shared_call_llm


def call_llm(system_prompt: str, user_prompt: str, model: str,
             temperature: float = 0.2, max_tokens: int = 2048,
             timeout: int = 120, *,
             ollama_key_state_path: str | Path | None = None) -> str:
    return _shared_call_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        ollama_key_state_path=ollama_key_state_path,
    )


def extract_code(raw: str) -> str:
    """Strip markdown fences, return clean Python source."""
    fence = re.search(r"```(?:python)?\s*([\s\S]+?)\s*```", raw)
    if fence:
        return fence.group(1).strip()

    text = raw.strip()
    if text.startswith("```"):
        _, _, remainder = text.partition("\n")
        return remainder.strip()
    return text


def validate_harness(code: str) -> None:
    """Fail fast before writing an unusable harness to disk."""
    if not code.strip():
        raise ValueError("LLM generated empty Python harness")
    if "```" in code:
        raise ValueError(f"LLM generated Python still contains markdown fences:\n\n{code}")

    try:
        tree = ast.parse(code, filename="<harness>")
    except SyntaxError as e:
        raise ValueError(f"LLM generated invalid Python:\n{e}\n\n{code}") from e

    has_test_one_input = any(
        isinstance(node, ast.FunctionDef) and node.name == "TestOneInput"
        for node in ast.walk(tree)
    )
    if not has_test_one_input:
        raise ValueError("LLM generated harness missing TestOneInput(data)")

    if "atheris.Setup" not in code:
        raise ValueError("LLM generated harness missing atheris.Setup(...)")
    if "atheris.Fuzz" not in code:
        raise ValueError("LLM generated harness missing atheris.Fuzz()")
