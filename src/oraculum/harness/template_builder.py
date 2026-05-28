import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .import_resolver import resolve_import

TEMPLATE_BUILTINS = {"re", "sys", "atheris", "os"}


def build_skeleton(
    artifact: dict,
    spec: dict,
    repo_root: str,
    corpus_dir: str,
) -> str:
    f       = artifact["finding"]
    meta    = spec.get("_meta", {})
    decision = spec.get("decision", {})
    research = spec.get("research", {})
    oracle  = spec.get("oracle_check", {})
    fuzz    = spec.get("fuzz_guidance", {})

    rule_id          = f.get("rule_id", "Unknown")
    function_name    = meta.get("function") or artifact.get("function", {}).get("name", "")
    file_path        = meta.get("file") or f.get("file", "")
    input_strategy   = meta.get("input_strategy", "direct_params")
    oracle_approach  = decision.get("oracle_approach", "return_value")
    build_mock       = decision.get("build_mock", False)

    # Resolve import
    raw_import   = resolve_import(file_path, function_name, repo_root)
    import_stmts = raw_import if isinstance(raw_import, list) else [raw_import]

    # Extra imports — skip builtins and unittest.mock (template handles it)
    extra_imports = []
    for m in research.get("additional_imports", []):
        if m.strip() not in TEMPLATE_BUILTINS:
            extra_imports.append(f"import {m}")

    # Normalize trigger_patterns
    trigger_patterns = oracle.get("trigger_patterns", [])
    if isinstance(trigger_patterns, str):
        trigger_patterns = json.loads(trigger_patterns)

    # Normalize tainted_params
    tainted_params = meta.get("tainted_params", [])
    if isinstance(tainted_params, str):
        tainted_params = json.loads(tainted_params)

    # Build function_signature — fallback if spec omits it
    function_signature = meta.get("function_signature") or (
        "def {}({})".format(
            function_name,
            ", ".join(p["name"] for p in tainted_params) if tainted_params else "...",
        )
    )

    # Extract research fields
    patch_target    = research.get("target_to_record", "")
    target_arg_index = research.get("target_arg_index")
    target_arg_name  = research.get("record_selector", "")
    capture_what    = research.get("return_selector", "")
    allowed_root    = (research.get("filesystem_watch") or {}).get("allowed_root", "")

    # Render
    templates_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(templates_dir)))
    env.filters["tojson"] = lambda v: json.dumps(v, ensure_ascii=False)
    template = env.get_template("base_harness.j2")

    return template.render(
        rule_id            = rule_id,
        function_name      = function_name,
        file_path          = file_path,
        extra_imports      = extra_imports,
        import_stmts       = import_stmts,
        repo_root          = repo_root,
        corpus_dir         = corpus_dir,
        input_strategy     = input_strategy,
        oracle_approach    = oracle_approach,
        build_mock         = build_mock,
        patch_target       = patch_target,
        target_arg_index   = target_arg_index,
        target_arg_name    = target_arg_name,
        capture_what       = capture_what,
        allowed_root       = allowed_root,
        tainted_params     = tainted_params,
        trigger_patterns   = trigger_patterns,
        raise_message      = oracle.get("raise_message_template", ""),
        function_signature = function_signature,
        skip_condition     = fuzz.get("skip_condition", "False"),
    )
