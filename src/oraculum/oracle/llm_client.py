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

    # 2. Fallback: decode from each object start. raw_decode correctly ignores
    # braces inside JSON strings, unlike a hand-rolled brace counter.
    decoder = json.JSONDecoder()
    for start, ch in enumerate(text):
        if ch != "{":
            continue
        try:
            data, _end = decoder.raw_decode(text[start:])
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data

    raise ValueError(f"LLM output not valid JSON:\n{raw_text}")

def normalize_oracle_spec(spec: dict) -> dict:
    """Normalize common compact oracle responses into the canonical schema."""
    normalized = dict(spec)
    monitor = normalized.setdefault("monitor", {})
    if isinstance(monitor, dict):
        raw_target = monitor.get("target")
        target = raw_target if isinstance(raw_target, dict) else {}
        raw_capture = monitor.get("capture")
        capture = raw_capture if isinstance(raw_capture, dict) else {}
        capture_args = monitor.get("capture_args")
        first_capture_arg = (
            capture_args[0]
            if isinstance(capture_args, list) and capture_args and isinstance(capture_args[0], dict)
            else {}
        )
        if "patch_target" not in monitor:
            module = str(target.get("module") or monitor.get("module") or "").strip()
            callable_name = str(
                target.get("callable")
                or target.get("function")
                or (raw_target if isinstance(raw_target, str) else "")
            ).strip()
            if module == "__builtin__":
                module = "builtins"
            if not module and callable_name in {"eval", "exec", "open", "input", "compile"}:
                module = "builtins"
            monitor["patch_target"] = (
                f"{module}.{callable_name}"
                if module and callable_name
                else callable_name or None
            )
        if "target_arg_index" not in monitor:
            monitor["target_arg_index"] = (
                capture.get("argument_index")
                if "argument_index" in capture
                else capture.get("arg_index", first_capture_arg.get("index"))
            )
        if "target_arg_name" not in monitor:
            monitor["target_arg_name"] = capture.get("name", first_capture_arg.get("name"))
        if "capture_what" not in monitor:
            monitor["capture_what"] = (
                str(capture.get("name") or "")
                or str(first_capture_arg.get("name") or "")
                or str(capture.get("description") or "")
                or "captured value"
            )
        if "additional_imports" not in monitor:
            monitor["additional_imports"] = []

    oracle_check = normalized.setdefault("oracle_check", {})
    if isinstance(oracle_check, dict):
        predicate = oracle_check.get("predicate")
        if "condition_description" not in oracle_check:
            oracle_check["condition_description"] = str(
                oracle_check.get("description") or predicate or "oracle condition"
            )
        if "trigger_patterns" not in oracle_check:
            regex = oracle_check.get("regex")
            predicates = oracle_check.get("predicates")
            if isinstance(regex, str) and regex:
                oracle_check["trigger_patterns"] = [regex]
            elif isinstance(predicates, list):
                oracle_check["trigger_patterns"] = [
                    str(item.get("pattern"))
                    for item in predicates
                    if isinstance(item, dict) and item.get("pattern")
                ]
            else:
                oracle_check["trigger_patterns"] = []
        strategy = monitor.get("strategy") if isinstance(monitor, dict) else ""
        if strategy in {"recorded_call", "return_value"} and not oracle_check["trigger_patterns"]:
            oracle_check["trigger_patterns"] = [r"[\s\S]+"]
        if "raise_type" not in oracle_check:
            oracle_check["raise_type"] = "RuntimeError"
        if "raise_message_template" not in oracle_check:
            oracle_check["raise_message_template"] = "ORACULUM_VIOLATION: captured={captured}"

    fuzz_guidance = normalized.setdefault("fuzz_guidance", {})
    if isinstance(fuzz_guidance, dict):
        if "seed_corpus" not in fuzz_guidance:
            seeds = fuzz_guidance.get("seeds")
            fuzz_guidance["seed_corpus"] = seeds if isinstance(seeds, list) else []
        if "skip_condition" not in fuzz_guidance:
            fuzz_guidance["skip_condition"] = "False"

    return normalized


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

    valid_strategies = {"return_value", "recorded_call", "filesystem_state"}
    if monitor["strategy"] not in valid_strategies:
        raise ValueError(f"monitor.strategy invalid: '{monitor['strategy']}'. Must be one of {valid_strategies}")

    if monitor["strategy"] == "recorded_call" and not monitor["patch_target"]:
        raise ValueError("monitor.patch_target must be set when strategy is 'recorded_call'")

    # oracle_check fields
    oracle_check = spec["oracle_check"]
    for field in ["condition_description", "trigger_patterns", "raise_type", "raise_message_template"]:
        if field not in oracle_check:
            raise ValueError(f"oracle_check missing field: '{field}'")

    if monitor["strategy"] in {"recorded_call", "return_value"} and not oracle_check["trigger_patterns"]:
        raise ValueError("oracle_check.trigger_patterns must not be empty for recorded_call/return_value")

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
