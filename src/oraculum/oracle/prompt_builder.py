import json
from pathlib import Path


def load_system_prompt(prompts_dir: str, strategy: str | None = None) -> str:
    filenames = {
        "recorded_call": "oracle_system_recorded_call.txt",
        "return_value": "oracle_system_return_value.txt",
        "filesystem_state": "oracle_system_filesystem_state.txt",
    }
    filename = filenames.get(strategy or "", "oracle_system.txt")
    return Path(prompts_dir, filename).read_text(encoding="utf-8")


def build_user_prompt(finding: dict, function_signature: str,
                       input_strategy: str, prompts_dir: str,
                       answers: list | dict | None = None,
                       classification: dict | None = None) -> str:
    template = Path(prompts_dir, "oracle_user.txt").read_text(encoding="utf-8")
    if isinstance(answers, list):
        answers_text = "\n".join(f"- {a}" for a in answers) if answers else "(not provided)"
    elif isinstance(answers, dict):
        answers_text = json.dumps(answers, indent=2, ensure_ascii=False)
    else:
        answers_text = "(not provided)"
    classification_text = (
        json.dumps(classification, indent=2, ensure_ascii=False)
        if classification
        else "(not provided)"
    )
    return template.format(
        finding_json       = json.dumps(finding, indent=2, ensure_ascii=False),
        function_signature = function_signature,
        input_strategy     = input_strategy,
        answers            = answers_text,
        classification     = classification_text,
    )
