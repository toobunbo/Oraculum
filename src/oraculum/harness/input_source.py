"""Detect Flask request input-source for OWASP-Benchmark-style view functions.

OWASP Benchmark for Python nests vulnerable handlers inside ``def init(app):``
and reads attacker input from ``request.form`` / ``request.cookies`` /
``request.args`` / ``request.headers`` / ``request.path`` / ``request.view_args``.
To call such a handler under a fuzzer we must set up the matching Flask request
context, so we need to know which source carries the tainted value and which key.

This module performs a deterministic, dependency-free ``ast`` scan of the target
source file. It returns the first concrete request-source access it finds inside
the handler body. The detection mirrors the intent of
``config/queries/python/web_params.ql`` (CodeQL) but uses the stdlib ``ast``
module so it works without the CodeQL CLI.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

# request attribute -> our canonical source kind
_SOURCE_KINDS = {
    "form": "form",
    "cookies": "cookie",
    "args": "args",
    "headers": "header",
    "view_args": "view_args",
}


@dataclass(frozen=True)
class InputSource:
    """Where the tainted request value comes from."""

    kind: str  # form | cookie | args | header | view_args | path | unknown
    key: str | None  # the parameter/cookie/header name, or None for path


def detect_input_source(source_path: Path, function_name: str) -> InputSource:
    """Detect the request input source used by ``function_name``.

    Scans the AST of ``source_path`` for ``request.<attr>.get/getlist("KEY")``
    or bare ``request.path`` accesses that appear inside the target function
    (including handlers nested in ``init(app)``). Returns ``kind="unknown"``
    if nothing is recognised.
    """
    try:
        tree = ast.parse(Path(source_path).read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return InputSource(kind="unknown", key=None)

    handler = _find_function(tree, function_name)
    if handler is None:
        return InputSource(kind="unknown", key=None)

    # 1. request.<form|cookies|args|headers|view_args>.get/getlist("KEY")
    #    or request.<kind>["KEY"].
    for node in ast.walk(handler):
        src = _request_access(node)
        if src is not None:
            return src

    # 2. Raw request.query_string access (OWASP pattern:
    #    query_string = request.query_string; paramLoc = query_string.find(b"KEY")).
    #    Treat as args and pull the key out of the .find() literal.
    qs = _query_string_source(handler, function_name)
    if qs is not None:
        return qs

    return InputSource(kind="unknown", key=None)


def _find_function(tree: ast.AST, name: str) -> ast.FunctionDef | None:
    """Find a function def named ``name``, even if nested inside ``init(app)``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    return None


def _request_access(node: ast.AST) -> InputSource | None:
    """Match ``request.<form|cookies|args|headers|view_args>.get/getlist(KEY)``
    or ``request.path`` at a single AST node."""
    # request.<kind>.get/getlist("KEY")  or  request.<kind>["KEY"]
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in {"get", "getlist"}:
            src = _request_attr_kind(func.value)
            key = _literal_key(node.args)
            if src is not None:
                return InputSource(kind=src, key=key)

    # request.<kind>["KEY"]
    if isinstance(node, ast.Subscript):
        src = _request_attr_kind(node.value)
        key = _literal_key_node(node.slice)
        if src is not None:
            return InputSource(kind=src, key=key)

    # request.path  (bare attribute access — value is the URL path)
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "path"
        and _is_request(node.value)
    ):
        return InputSource(kind="path", key=None)
    return None


def _query_string_source(handler: ast.AST, function_name: str) -> InputSource | None:
    """Detect a raw ``request.query_string`` read (OWASP pattern:
    ``qs = request.query_string; loc = qs.find(b"KEY")``) and treat it as the
    ``args`` source. The key comes from the ``.find()`` literal when present,
    otherwise from the function name with its HTTP-method suffix stripped.
    """
    has_qs = False
    find_key: str | bytes | None = None
    for node in ast.walk(handler):
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "query_string"
            and _is_request(node.value)
        ):
            has_qs = True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "find"
            and node.args
        ):
            candidate = _literal_key_node(node.args[0])
            if isinstance(candidate, (str, bytes)) and len(candidate) > 1:
                find_key = candidate
    if not has_qs:
        return None
    if isinstance(find_key, bytes):
        find_key = find_key.decode("utf-8", "ignore")
    if not isinstance(find_key, str) or not find_key:
        for suffix in ("_post", "_get", "_put", "_delete", "_patch"):
            if function_name.endswith(suffix):
                find_key = function_name[: -len(suffix)]
                break
        else:
            find_key = function_name
    return InputSource(kind="args", key=find_key)


def _request_attr_kind(node: ast.AST) -> str | None:
    """If ``node`` is ``request.<kind>``, return the canonical kind."""
    if isinstance(node, ast.Attribute) and _is_request(node.value):
        return _SOURCE_KINDS.get(node.attr)
    return None


def _is_request(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "request"


def _literal_key(args: list[ast.AST]) -> str | None:
    """First string literal among call args (the dict/cookie/header key)."""
    if not args:
        return None
    return _literal_key_node(args[0])


def _literal_key_node(node: ast.AST) -> str | None:
    try:
        return ast.literal_eval(node) if isinstance(node, ast.Constant) else None
    except (ValueError, TypeError):
        return None
