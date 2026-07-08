"""Derive compact return-shape metadata for classification prompts."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any


def analyze_returns(artifact: dict[str, Any]) -> dict[str, Any]:
    """Return a compact syntactic return signal for an enriched finding artifact."""
    source_path = _source_file_path(artifact)
    if source_path is None or not source_path.is_file():
        return _unknown("source file not found")

    try:
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        return _unknown(f"source parse failed: {exc}")

    node = _find_function_node(tree, artifact)
    if node is None:
        return _unknown("target function not found")

    returns = _collect_returns(node)
    if not returns:
        return {"kind": "none", "exprs": []}

    has_value = any(not _is_none_like(ret.value) for ret in returns)
    has_none = any(_is_none_like(ret.value) for ret in returns)

    if has_value and has_none:
        kind = "mixed"
    elif has_value:
        kind = "value"
    else:
        kind = "none"

    exprs: list[str] = []
    for ret in returns:
        if _is_none_like(ret.value):
            if kind == "mixed":
                exprs.append("None")
            continue
        try:
            exprs.append(ast.unparse(ret.value))
        except Exception:
            exprs.append("<unparseable>")
    return {"kind": kind, "exprs": exprs}


def _unknown(note: str) -> dict[str, Any]:
    return {"kind": "unknown", "exprs": [], "notes": [note]}


def _source_file_path(artifact: dict[str, Any]) -> Path | None:
    source = artifact.get("source") if isinstance(artifact.get("source"), dict) else {}
    finding = artifact.get("finding") if isinstance(artifact.get("finding"), dict) else {}
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}
    root = source.get("vhx_repo_root")
    file_path = function.get("file") or finding.get("file")
    if not root or not file_path:
        return None
    
    path = Path(str(root)) / str(file_path)
    if path.is_file():
        return path
        
    # Fallback for relative or mismatch paths in cloned workspace
    root_str = str(root)
    for marker in ["tests/mini_benchmark/vhx_root", "vhx_root"]:
        if marker in root_str:
            rel_parts = root_str.split(marker, 1)[1].lstrip("/")
            fallback_path = Path.cwd() / marker / rel_parts / str(file_path)
            if fallback_path.is_file():
                return fallback_path
                
    fallback_simple = Path.cwd() / "tests/mini_benchmark/vhx_root/repos/python/mini-bench" / str(file_path)
    if fallback_simple.is_file():
        return fallback_simple

    return path


def _find_function_node(
    tree: ast.AST,
    artifact: dict[str, Any],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    function = artifact.get("function") if isinstance(artifact.get("function"), dict) else {}
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


def _collect_returns(node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Return]:
    collector = _ReturnCollector()
    for statement in node.body:
        collector.visit(statement)
    return collector.returns


class _ReturnCollector(ast.NodeVisitor):
    """Collect returns from the current function body, excluding nested scopes."""

    def __init__(self) -> None:
        self.returns: list[ast.Return] = []

    def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
        self.returns.append(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:  # noqa: N802
        return

    def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
        return


def _is_none_like(node: ast.expr | None) -> bool:
    return node is None or (isinstance(node, ast.Constant) and node.value is None)


def _as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0
