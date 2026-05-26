from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from .csv_loader import FuncRow, SigRow


def build_signature(function_name: str, file: str, signatures: list[SigRow]) -> str:
    params = [r for r in signatures
              if r.name == function_name and r.file == file
              and r.param_name not in ("self", "cls")]
    if not params:
        return f"def {function_name}(self)"
    parts = [f"{r.param_name}: {r.param_type}" if r.param_type
             else r.param_name for r in params]
    return f"def {function_name}({', '.join(parts)})"

def get_input_strategy(function_name: str, file: str,
                        signatures: list[SigRow], functions: list[FuncRow]) -> str:
    # Check if function has real (non-self/cls) parameters in the signatures CSV
    has_real_params = any(r for r in signatures
                          if r.name == function_name and r.file == file
                          and r.param_name not in ("self", "cls"))
    if has_real_params:
        return "direct_params"

    # No real params → look up the function in functions.csv
    func = next((r for r in functions
                 if r.name == function_name and r.file == file), None)

    # Flask class-based views: scope contains "Class" (e.g. "Class MyView")
    if func and "Class" in func.scope:
        return "flask_view"

    # Fallback heuristic: if the function exists in functions.csv but has no
    # real params (only self), it's almost certainly a Flask MethodView / View
    # method — treat it as flask_view so the LLM uses request.* to get input.
    if func is not None:
        only_self = all(r.param_name in ("self", "cls")
                        for r in signatures
                        if r.name == function_name and r.file == file)
        if only_self:
            return "flask_view"

    return "direct_params"


def build_signature_from_artifact(artifact: dict[str, Any]) -> str:
    """Build a compact Python signature from the source file captured by ingest."""
    function = _function_object(artifact)
    function_name = str(function.get("name") or "unknown")
    node = _find_function_node(artifact)
    if node is None:
        return f"def {function_name}(self)"
    return _format_function_signature(node)


def get_input_strategy_from_artifact(artifact: dict[str, Any]) -> str:
    """Choose the oracle input strategy from source signature and function scope."""
    node = _find_function_node(artifact)
    if node is not None and _has_real_params(node):
        return "direct_params"

    scope = str(_function_object(artifact).get("scope") or "")
    if "Class" in scope:
        return "flask_view"
    if node is not None:
        return "flask_view" if _has_only_self_or_cls(node) else "direct_params"
    return "direct_params"


def _find_function_node(artifact: dict[str, Any]) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    source_path = _source_file_path(artifact)
    if source_path is None or not source_path.is_file():
        return None

    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return None

    function = _function_object(artifact)
    function_name = str(function.get("name") or "")
    start_line = _as_int(function.get("start_line"))
    end_line = _as_int(function.get("end_line"))

    matches: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != function_name:
            continue
        node_start = getattr(node, "lineno", 0)
        if start_line and end_line and not (start_line <= node_start <= end_line):
            continue
        matches.append(node)

    if not matches:
        return None
    return min(matches, key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno)


def _source_file_path(artifact: dict[str, Any]) -> Path | None:
    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    root = source.get("vhx_repo_root")
    file_path = finding.get("file")
    if not root or not file_path:
        return None
    return Path(str(root)) / str(file_path)


def _format_function_signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    args = node.args
    params: list[str] = []

    for arg in [*args.posonlyargs, *args.args]:
        if arg.arg in {"self", "cls"}:
            continue
        params.append(_format_arg(arg))

    if args.vararg is not None:
        params.append("*" + _format_arg(args.vararg))
    elif args.kwonlyargs:
        params.append("*")

    for arg in args.kwonlyargs:
        params.append(_format_arg(arg))

    if args.kwarg is not None:
        params.append("**" + _format_arg(args.kwarg))

    positional = [*args.posonlyargs, *args.args]
    if not params and positional and _has_only_self_or_cls(node):
        params.append("self")
    return f"def {node.name}({', '.join(params)})"


def _format_arg(arg: ast.arg) -> str:
    annotation = _annotation(arg.annotation)
    if annotation:
        return f"{arg.arg}: {annotation}"
    return arg.arg


def _annotation(node: ast.expr | None) -> str:
    if node is None:
        return ""
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _has_real_params(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(arg.arg not in {"self", "cls"} for arg in [*node.args.posonlyargs, *node.args.args])


def _has_only_self_or_cls(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    positional = [*node.args.posonlyargs, *node.args.args]
    return all(arg.arg in {"self", "cls"} for arg in positional)


def _function_object(artifact: dict[str, Any]) -> dict[str, Any]:
    function = artifact.get("function")
    return function if isinstance(function, dict) else {}


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
