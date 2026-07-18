import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from .exploit_signatures import seeds_for, signatures_for
from .import_resolver import detect_init_app, resolve_import
from .input_source import detect_input_source

TEMPLATE_BUILTINS = {"re", "sys", "atheris", "os"}


def build_skeleton(
    artifact: dict,
    spec: dict,
    repo_root: str,
    corpus_dir: str,
) -> str:
    f      = artifact["finding"]
    meta    = spec.get("_meta", {})
    monitor = spec.get("monitor", {})
    oracle  = spec.get("oracle_check", {})
    fuzz    = spec.get("fuzz_guidance", {})

    rule_id          = f.get("rule_id", "Unknown")
    function_name    = meta.get("function") or artifact.get("function", {}).get("name", "")
    file_path        = meta.get("file") or f.get("file", "")
    input_strategy   = meta.get("input_strategy", "direct_params")
    monitor_strategy = monitor.get("strategy", "return_value")

    source_path = _resolve_source_path(repo_root, file_path)
    is_init_app = detect_init_app(source_path, function_name)

    # Flask framework path: deterministic, COMPLETE harness (no LLM fill).
    # Used for OWASP-Benchmark-style handlers nested in ``def init(app):``.
    if (
        input_strategy == "flask_view"
        and is_init_app
        and monitor_strategy == "recorded_call"
    ):
        return _build_flask_skeleton(
            rule_id=rule_id,
            function_name=function_name,
            file_path=file_path,
            repo_root=repo_root,
            corpus_dir=corpus_dir,
            monitor=monitor,
            oracle=oracle,
            fuzz=fuzz,
            source_path=source_path,
            templates_dir=Path(__file__).parent / "templates",
        )

    # Default path: skeleton with [FILL HERE], completed by the LLM.
    raw_import = resolve_import(file_path, function_name, repo_root)
    import_stmts = raw_import if isinstance(raw_import, list) else [raw_import]

    extra_imports = []
    for m in monitor.get("additional_imports", []):
        if m.strip() not in TEMPLATE_BUILTINS:
            extra_imports.append(f"import {m}")

    trigger_patterns = oracle.get("trigger_patterns", [])
    if isinstance(trigger_patterns, str):
        trigger_patterns = json.loads(trigger_patterns)

    tainted_params = meta.get("tainted_params", [])
    if isinstance(tainted_params, str):
        tainted_params = json.loads(tainted_params)

    function_signature = meta.get("function_signature") or (
        "def {}({})".format(
            function_name,
            ", ".join(p["name"] for p in tainted_params) if tainted_params else "...",
        )
    )

    capture_what = oracle.get("capture_what") or monitor.get("capture_what", "")

    templates_dir = Path(__file__).parent / "templates"
    env = _make_env(templates_dir)
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
        monitor_strategy   = monitor_strategy,
        patch_target       = monitor.get("patch_target"),
        target_arg_index   = monitor.get("target_arg_index"),
        target_arg_name    = monitor.get("target_arg_name"),
        capture_what       = capture_what,
        condition_desc     = oracle.get("condition_description", ""),
        tainted_params     = tainted_params,
        trigger_patterns   = trigger_patterns,
        raise_message      = oracle.get("raise_message_template", ""),
        function_signature = function_signature,
        skip_condition     = fuzz.get("skip_condition", "False"),
    )


def _build_flask_skeleton(
    *,
    rule_id: str,
    function_name: str,
    file_path: str,
    repo_root: str,
    corpus_dir: str,
    monitor: dict,
    oracle: dict,
    fuzz: dict,
    source_path: Path | None,
    templates_dir: Path,
) -> str:
    raw_import = resolve_import(file_path, function_name, repo_root)
    import_stmts = [raw_import] if isinstance(raw_import, str) else raw_import

    src = (
        detect_input_source(source_path, function_name)
        if source_path
        else None
    )
    input_kind = src.kind if src else "unknown"
    input_key = (src.key if src and src.key else "")

    # Prefer the clean ``monitor.target`` (e.g. "subprocess.run") over the LLM's
    # ``patch_target`` (sometimes malformed like "subprocess.subprocess.run").
    patch_target = monitor.get("target") or monitor.get("patch_target")

    # Oracle precision: prefer deterministic exploit-signatures for the rule
    # (tests exploitability, not mere reachability) over the LLM's loose
    # trigger_patterns. Fall back to LLM patterns only when the rule is unknown.
    registry_patterns = signatures_for(rule_id)
    trigger_patterns = (
        registry_patterns
        if registry_patterns
        else oracle.get("trigger_patterns", [])
    )
    if isinstance(trigger_patterns, str):
        trigger_patterns = json.loads(trigger_patterns)

    registry_seeds = seeds_for(rule_id)
    if registry_seeds:
        seed_corpus = registry_seeds
    else:
        seed_corpus = fuzz.get("seed_corpus", []) if isinstance(fuzz, dict) else []
        if not isinstance(seed_corpus, list):
            seed_corpus = []

    raise_message = oracle.get("raise_message_template") or (
        "ORACULUM_VIOLATION: captured={captured}"
    )

    env = _make_env(templates_dir)
    template = env.get_template("base_harness_flask.j2")
    return template.render(
        rule_id          = rule_id,
        function_name    = function_name,
        file_path        = file_path,
        import_stmts     = import_stmts,
        repo_root        = repo_root,
        corpus_dir       = corpus_dir,
        input_kind       = input_kind,
        input_key        = input_key,
        patch_target     = patch_target,
        trigger_patterns = trigger_patterns,
        raise_message    = raise_message,
        seed_corpus      = seed_corpus,
    )


def _make_env(templates_dir: Path) -> Environment:
    env = Environment(loader=FileSystemLoader(str(templates_dir)))
    env.filters["tojson"] = lambda v: json.dumps(v, ensure_ascii=False)
    return env


def _resolve_source_path(repo_root: str, file_path: str) -> Path | None:
    if not file_path:
        return None
    direct = Path(file_path)
    if direct.is_file():
        return direct
    if repo_root:
        joined = Path(repo_root) / file_path
        if joined.is_file():
            return joined
    return None
