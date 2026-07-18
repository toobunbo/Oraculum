import ast
import os
from pathlib import Path


def resolve_import(file_path: str, function_name: str, repo_root: str) -> str:
    """
    Convert file path + function name -> Python import statement.

    Module-level target:
      "superset/utils/core.py" + "sanitize_svg_content"
      -> "from superset.utils.core import sanitize_svg_content"

    OWASP-Benchmark-style target (nested inside ``def init(app):``):
      "testcode/BenchmarkTest00165.py" + "BenchmarkTest00165_post"
      -> "import testcode.BenchmarkTest00165 as _target_mod"
      The harness then calls ``_target_mod.init(app)`` and extracts the
      route handler via ``app.view_functions`` (see base_harness flask branch).

    Class-method target (method inside a class, not in init):
      "dsvw.py" + "do_GET" (method of ReqHandler)
      -> "import dsvw as _target_mod"
    """
    rel = file_path
    if repo_root and file_path.startswith(repo_root):
        rel = file_path[len(repo_root):].lstrip(os.sep)

    module_path = rel.replace(os.sep, "/").removesuffix(".py")
    module = module_path.replace("/", ".")

    if module.endswith(".__init__"):
        module = module[: -len(".__init__")]

    source_path = _source_path(repo_root, file_path)
    if source_path:
        if detect_init_app(source_path, function_name):
            return f"import {module} as _target_mod"
        if detect_class_method(source_path, function_name):
            return f"import {module} as _target_mod"

    return f"from {module} import {function_name}"


def detect_class_method(source_path: Path | str | None, function_name: str) -> bool:
    """Return True when ``function_name`` is a method inside a class
    (but NOT nested inside an init(app) function)."""
    if not source_path:
        return False
    path = Path(source_path)
    if not path.is_file():
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return False
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == function_name:
                    return True
    return False


def detect_init_app(source_path: Path | str | None, function_name: str) -> bool:
    """Return True when ``function_name`` is a route handler nested inside an
    OWASP-Benchmark-style ``def init(app):`` registration helper.

    Detection rule: the source parses, an ``init`` function exists at module
    level, and ``function_name`` is NOT itself a module-level function (i.e. it
    is nested inside ``init``). This is deliberately conservative: any failure
    to read/parse returns False so the default ``from ... import ...`` path is
    used.
    """
    if not source_path:
        return False
    path = Path(source_path)
    if not path.is_file():
        return False
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except (OSError, SyntaxError):
        return False

    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "init":
            for child in ast.walk(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name == function_name:
                    return True
            break
    return False


def _source_path(repo_root: str | None, file_path: str) -> Path | None:
    if not file_path:
        return None
    candidate = Path(file_path)
    if candidate.is_file():
        return candidate
    if repo_root:
        joined = Path(repo_root) / file_path
        if joined.is_file():
            return joined
    return None
