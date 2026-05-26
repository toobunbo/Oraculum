import json
import logging
import os
from pathlib import Path

import yaml

from oraculum.harness.paths import resolve_harness_paths
from oraculum.harness.runner import generate_one_harness
from oraculum.oracle.paths import target_id_for_artifact

from .llm_client import validate_harness


def run(finding_path: str, spec_path: str,
        config_path: str = "config/harness.yaml") -> str:

    config = yaml.safe_load(Path(config_path).read_text())

    # Override model using .env variables if they exist
    llm_provider = os.getenv("LLM_PROVIDER")
    llm_model    = os.getenv("LLM_MODEL")
    if llm_provider and llm_model:
        config["model"] = f"{llm_provider}/{llm_model}"
    elif llm_model:
        config["model"] = llm_model

    finding = json.loads(Path(finding_path).read_text(encoding="utf-8"))
    spec    = json.loads(Path(spec_path).read_text(encoding="utf-8"))

    f        = finding["finding"]
    repo     = f["repo_name"]
    lang     = f["lang"]
    function = finding.get("function", {}).get("name", "unknown")
    target_id = spec.get("_meta", {}).get("target_id") or target_id_for_artifact(finding)
    output_dir = Path(os.environ.get("ORACULUM_OUTPUT_DIR", "output"))
    paths = resolve_harness_paths(output_dir=output_dir, lang=lang, repo=repo)
    out = paths.fuzz_targets_dir / f"{target_id}.py"
    corpus_dir = paths.fuzz_corpus_dir / target_id

    logging.info(f"[Stage2] function  : {function}")
    logging.info(f"[Stage2] rule_id   : {f['rule_id']}")
    logging.info(f"[Stage2] strategy  : {spec.get('_meta', {}).get('input_strategy')}"
                 f" / {spec.get('monitor', {}).get('strategy')}")

    logging.info(f"[Stage2] skeleton built, calling {config['model']} ...")

    code = generate_one_harness(
        artifact=finding,
        oracle_spec=spec,
        corpus_dir=corpus_dir,
        config=config,
        prompts_dir=Path(config["prompts_dir"]),
        model=config["model"],
    )
    validate_harness(code)

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(code, encoding="utf-8")

    seed_corpus = spec.get("fuzz_guidance", {}).get("seed_corpus", [])
    if seed_corpus:
        corpus_dir.mkdir(parents=True, exist_ok=True)
        for i, seed in enumerate(seed_corpus):
            (corpus_dir / f"seed_{i:03d}").write_bytes(
                seed.encode("utf-8", errors="replace")
            )
        logging.info(f"[Stage2] corpus    : {corpus_dir} ({len(seed_corpus)} seeds)")

    logging.info(f"[Stage2] output    : {out}")
    logging.info("\n[Stage2] Run with:")
    logging.info(f"  python {out} -atheris_runs=10000")
    if seed_corpus:
        logging.info(f"  python {out} {corpus_dir}")

    return str(out)
