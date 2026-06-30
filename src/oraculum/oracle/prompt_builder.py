import json
from pathlib import Path


def load_system_prompt(prompts_dir: str, strategy: str | None = None) -> str:
    if strategy == "recorded_call":
        filename = "oracle_system_recorded_call.txt"
    elif strategy == "return_value":
        filename = "oracle_system_return_value.txt"
    elif strategy == "filesystem_state":
        filename = "oracle_system_filesystem_state.txt"
    else:
        filename = "oracle_system.txt"
    return Path(prompts_dir, filename).read_text(encoding="utf-8")


def build_user_prompt(finding: dict, function_signature: str,
                       input_strategy: str, prompts_dir: str,
                       answers: list | dict | None = None,
                       classification: dict | None = None) -> str:
    template = Path(prompts_dir, "oracle_user.txt").read_text(encoding="utf-8")
    
    if isinstance(answers, dict):
        answers_text = json.dumps(answers, indent=2, ensure_ascii=False)
    elif isinstance(answers, list):
        answers_text = "\n".join(f"- {a}" for a in answers)
    else:
        answers_text = "(not provided)"

    prompt = template.format(
        finding_json       = json.dumps(finding, indent=2, ensure_ascii=False),
        function_signature = function_signature,
        input_strategy     = input_strategy,
        answers            = answers_text,
    )

    if classification:
        strategy = classification.get("strategy", "unknown")
        mock_guidance = classification.get("mock_guidance")
        prompt += f"\n\n## Classification Result\n- Strategy: {strategy}\n"
        if mock_guidance:
            prompt += f"- Mock Guidance: {json.dumps(mock_guidance, indent=2, ensure_ascii=False)}\n"

    return prompt
