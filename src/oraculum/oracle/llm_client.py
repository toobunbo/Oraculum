import json
import re
from pathlib import Path

from oraculum.llm.client import call_llm as _shared_call_llm


def call_llm(system_prompt: str, user_prompt: str, model: str,
             temperature: float = 0.2, max_tokens: int = 1024, timeout: int = 60,
             *, ollama_key_state_path: str | Path | None = None) -> str:
    return _shared_call_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        timeout=timeout,
        ollama_key_state_path=ollama_key_state_path,
    )


def parse_oracle_spec(raw_text: str) -> dict:
    text = raw_text.strip()

    # 1. Try extracting from ```json ... ``` or ``` ... ``` fence first
    fence = re.search(r"```(?:json)?\s*([\s\S]+?)\s*```", text)
    if fence:
        candidate = fence.group(1).strip()
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass  # fall through to next strategy

    # 2. Fallback: find the first balanced { ... } JSON object in the raw text.
    #    Handles LLMs that emit THINKING: ... text before a bare JSON block.
    start = text.find("{")
    if start != -1:
        depth = 0
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = text[start:i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        break  # found a {} block but it's not valid JSON

    raise ValueError(f"LLM output not valid JSON:\n{raw_text}")

def validate_oracle_spec(spec: dict) -> None:
    # Top-level blocks
    for block in ["monitor", "oracle_check", "fuzz_guidance", "_meta"]:
        if block not in spec:
            raise ValueError(f"oracle_spec missing block: '{block}'")

    # monitor fields
    monitor = spec["monitor"]
    for field in ["strategy", "patch_target", "capture_what", "additional_imports"]:
        if field not in monitor:
            raise ValueError(f"monitor missing field: '{field}'")

    valid_strategies = {"inspect_return", "patch_call", "catch_exception"}
    if monitor["strategy"] not in valid_strategies:
        raise ValueError(f"monitor.strategy invalid: '{monitor['strategy']}'. Must be one of {valid_strategies}")

    if monitor["strategy"] == "patch_call" and not monitor["patch_target"]:
        raise ValueError("monitor.patch_target must be set when strategy is 'patch_call'")

    # if monitor["strategy"] != "inspect_return" and spec["oracle_check"].get("trigger_patterns"):
    #     raise ValueError("oracle_check.trigger_patterns must be [] when strategy is not 'inspect_return'")

    # oracle_check fields
    oracle_check = spec["oracle_check"]
    for field in ["condition_description", "trigger_patterns", "raise_type", "raise_message_template"]:
        if field not in oracle_check:
            raise ValueError(f"oracle_check missing field: '{field}'")

    if monitor["strategy"] in {"patch_call", "inspect_return"} and not oracle_check["trigger_patterns"]:
        raise ValueError("oracle_check.trigger_patterns must not be empty for patch_call/inspect_return")

    # fuzz_guidance fields
    fuzz_guidance = spec["fuzz_guidance"]
    for field in ["seed_corpus", "skip_condition"]:
        if field not in fuzz_guidance:
            raise ValueError(f"fuzz_guidance missing field: '{field}'")
    if not isinstance(fuzz_guidance["seed_corpus"], list):
        raise ValueError("fuzz_guidance.seed_corpus must be a list")
    if not isinstance(fuzz_guidance["skip_condition"], str):
        raise ValueError("fuzz_guidance.skip_condition must be a string")

    # _meta fields
    meta = spec["_meta"]
    for field in ["function", "file", "input_strategy", "function_signature", "tainted_params"]:
        if field not in meta:
            raise ValueError(f"_meta missing field: '{field}'")

    valid_input_strategies = {"direct_params", "flask_view"}
    if meta["input_strategy"] not in valid_input_strategies:
        raise ValueError(f"_meta.input_strategy invalid: '{meta['input_strategy']}'")

    for i, param in enumerate(meta["tainted_params"]):
        for field in ["name", "index", "type"]:
            if field not in param:
                raise ValueError(f"tainted_params[{i}] missing field: '{field}'")
        if meta["input_strategy"] == "direct_params" and param["index"] < 0:
            raise ValueError(f"tainted_params[{i}].index must be >= 0 for direct_params strategy")
