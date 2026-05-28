import json
import logging
import os
import re


def call_llm(system_prompt: str, user_prompt: str, model: str,
             temperature: float = 0.2, max_tokens: int = 1024, timeout: int = 60) -> str:
    _silence_litellm_optional_provider_warnings()
    from litellm import completion

    logging.debug("\n========== LLM REQUEST ==========")
    logging.debug(f"[SYSTEM PROMPT]\n{system_prompt}\n")
    logging.debug(f"[USER PROMPT]\n{user_prompt}\n")

    response = completion(
        model=model,
        messages=[{"role": "system", "content": system_prompt},
                  {"role": "user",   "content": user_prompt}],
        temperature=temperature, max_tokens=max_tokens, timeout=timeout,
    )

    content = response.choices[0].message.content
    logging.debug(f"========== LLM RESPONSE ==========\n{content}\n==================================")
    return content


def _silence_litellm_optional_provider_warnings() -> None:
    """Suppress noisy LiteLLM warnings for optional providers we do not use."""
    os.environ.setdefault("LITELLM_LOG", "ERROR")
    for logger_name in ("LiteLLM", "litellm"):
        logging.getLogger(logger_name).setLevel(logging.ERROR)


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
                        break

    raise ValueError(f"LLM output not valid JSON:\n{raw_text}")

_VALID_APPROACHES = {"recorded_call", "return_value", "filesystem_state"}


def validate_oracle_spec(spec: dict) -> None:
    # Top-level blocks
    for block in ["decision", "research", "oracle_check", "fuzz_guidance", "_meta"]:
        if block not in spec:
            raise ValueError(f"oracle_spec missing block: '{block}'")

    # decision fields
    decision = spec["decision"]
    for field in ["q1_sink_dangerous", "q1_reason", "q2_observable_after_return",
                  "q2_reason", "build_mock", "oracle_approach", "confidence"]:
        if field not in decision:
            raise ValueError(f"decision missing field: '{field}'")

    if decision["oracle_approach"] not in _VALID_APPROACHES:
        raise ValueError(
            f"decision.oracle_approach invalid: '{decision['oracle_approach']}'. "
            f"Must be one of {_VALID_APPROACHES}"
        )

    approach = decision["oracle_approach"]

    # Q3 fields: required only when Q2 is true
    if decision.get("q2_observable_after_return"):
        for field in ["q3_accessible_in_memory", "q3_reason"]:
            if field not in decision:
                raise ValueError(f"decision missing field: '{field}' (required when Q2 is true)")

    # build_mock must be bool
    if not isinstance(decision["build_mock"], bool):
        raise ValueError(f"decision.build_mock must be bool, got: {type(decision['build_mock']).__name__}")

    # Decision Tree consistency: Q2/Q3 must match oracle_approach
    q2 = decision.get("q2_observable_after_return")
    if q2 is False and approach != "recorded_call":
        raise ValueError(
            f"decision.oracle_approach must be 'recorded_call' when Q2=false, got '{approach}'"
        )
    if q2 is True:
        q3 = decision.get("q3_accessible_in_memory")
        if q3 is True and approach != "return_value":
            raise ValueError(
                f"decision.oracle_approach must be 'return_value' when Q2=true and Q3=true, got '{approach}'"
            )
        if q3 is False and approach != "filesystem_state":
            raise ValueError(
                f"decision.oracle_approach must be 'filesystem_state' when Q2=true and Q3=false, got '{approach}'"
            )

    # research fields
    research = spec["research"]
    for field in ["target_to_record", "record_selector", "fake_return",
                  "return_selector", "assertion"]:
        if field not in research:
            raise ValueError(f"research missing field: '{field}'")

    # Approach-specific required research fields
    if approach == "recorded_call":
        if not research.get("target_to_record"):
            raise ValueError("research.target_to_record must be set for recorded_call")
        if research.get("target_arg_index") is None:
            raise ValueError("research.target_arg_index must be set for recorded_call")
    elif approach == "return_value":
        if not research.get("return_selector"):
            raise ValueError("research.return_selector must be set for return_value")
    elif approach == "filesystem_state":
        fsw = research.get("filesystem_watch")
        if not isinstance(fsw, dict) or not fsw.get("allowed_root"):
            raise ValueError("research.filesystem_watch.allowed_root must be set for filesystem_state")

    # oracle_check fields
    oracle_check = spec["oracle_check"]
    for field in ["condition_description", "trigger_patterns", "raise_type", "raise_message_template"]:
        if field not in oracle_check:
            raise ValueError(f"oracle_check missing field: '{field}'")

    if not oracle_check["trigger_patterns"]:
        raise ValueError("oracle_check.trigger_patterns must not be empty")

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
            raise ValueError(f"tainted_params[{i}].index must be >= 0 for direct_params")
