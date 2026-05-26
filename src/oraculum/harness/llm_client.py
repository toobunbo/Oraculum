import ast
import logging
import os
import re


def call_llm(system_prompt: str, user_prompt: str, model: str,
             temperature: float = 0.2, max_tokens: int = 2048,
             timeout: int = 120) -> str:
    _silence_litellm_optional_provider_warnings()
    from litellm import completion

    logging.debug("\n========== LLM REQUEST ==========")
    logging.debug(f"[SYSTEM PROMPT]\n{system_prompt}\n")
    logging.debug(f"[USER PROMPT]\n{user_prompt}\n")

    response = completion(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user",   "content": user_prompt},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
    )
    
    content = response.choices[0].message.content
    logging.debug(f"========== LLM RESPONSE ==========\n{content}\n==================================")
    return content


def _silence_litellm_optional_provider_warnings() -> None:
    """Suppress noisy LiteLLM warnings for optional providers we do not use."""
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    for logger_name in ("LiteLLM", "litellm"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)


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
