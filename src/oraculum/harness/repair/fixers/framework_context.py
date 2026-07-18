import re
import os


REPO_ROOT_RE = re.compile(r'REPO_ROOT\s*=\s*["\']([^"\']+)["\']')

INSTRUMENT_IMPORT_RE = re.compile(
    r'(with atheris\.instrument_imports\(\):)'
)

DJANGO_IMPORT_RE = re.compile(r"from django\b|import django\b")
FLASK_IMPORT_RE = re.compile(r"from flask\b|import flask\b")
FASTAPI_IMPORT_RE = re.compile(r"from fastapi\b|import fastapi\b")

# Catches `from X import app` where X is any module and `app` is the imported Flask object
FLASK_APP_IMPORT_RE = re.compile(r"from\s+(\S+)\s+import\s+.*\bapp\b")

# Secondary Flask detection: code patterns unique to Flask (not just imports)
# Catches harnesses that import `app` via project modules (e.g. `from server import app`)
# without a direct `from flask import ...` line
FLASK_CODE_PATTERN = re.compile(
    r"test_request_context|Flask\("
)

DJANGO_SETTINGS_MODULE = 'DJANGO_SETTINGS_MODULE'


def _detect_framework(source: str, repo_root: str) -> str:
    if DJANGO_IMPORT_RE.search(source) or re.search(r'django\.http', source):
        return "django"

    if FLASK_IMPORT_RE.search(source):
        return "flask"

    # Safer fallback: detect Flask via code patterns instead of `from app import app`
    # (which caused false positives on non-Flask projects with a module named "app")
    if FLASK_CODE_PATTERN.search(source) and FLASK_APP_IMPORT_RE.search(source):
        return "flask"

    if FASTAPI_IMPORT_RE.search(source):
        return "fastapi"

    return "none"


def _detect_repo_root(source: str) -> str:
    m = REPO_ROOT_RE.search(source)
    return m.group(1) if m else ""


def _find_settings_py(repo_root: str) -> str | None:
    if not repo_root or not os.path.isdir(repo_root):
        return None
    for root, dirs, files in os.walk(repo_root):
        if "settings.py" in files:
            rel = os.path.relpath(os.path.join(root, "settings.py"), repo_root)
            module = rel.replace("/", ".").replace(".py", "")
            if module.endswith(".settings"):
                return module
        if "settings" in dirs:
            settings_init = os.path.join(root, "settings", "__init__.py")
            if os.path.isfile(settings_init):
                if root == repo_root:
                    module = "settings"
                else:
                    rel = os.path.relpath(root, repo_root)
                    module = rel.replace("/", ".").replace(os.sep, ".")
                    module = f"{module}.settings"
                if module.endswith(".settings"):
                    return module
    return None


WSGI_SETTINGS_RE = re.compile(
    r'os\.environ\[?["\']DJANGO_SETTINGS_MODULE["\']\]?\s*=\s*["\']([^"\']+)["\']'
)


def _find_settings_from_wsgi(repo_root: str) -> str | None:
    if not repo_root or not os.path.isdir(repo_root):
        return None
    for root, dirs, files in os.walk(repo_root):
        depth = 0 if root == repo_root else len(os.path.relpath(root, repo_root).split(os.sep))
        if depth > 2:
            dirs.clear()
            continue
        if "wsgi.py" in files:
            wsgi_path = os.path.join(root, "wsgi.py")
            try:
                with open(wsgi_path, encoding='utf-8') as f:
                    content = f.read()
                m = WSGI_SETTINGS_RE.search(content)
                if m:
                    return m.group(1)
            except OSError:
                continue
    return None


def _inject_django_setup(source: str, repo_root: str) -> str:
    settings_module = _find_settings_py(repo_root)
    if settings_module is None:
        settings_module = _find_settings_from_wsgi(repo_root)
    if settings_module is None and repo_root:
        base = os.path.basename(repo_root.rstrip("/"))
        base = base.replace("-", "_").replace(" ", "_")
        settings_module = f"{base}.settings"

    if settings_module:
        boilerplate = (
            f'import django\n'
            f'os.environ.setdefault("{DJANGO_SETTINGS_MODULE}", "{settings_module}")\n'
            f'django.setup()\n\n'
        )
    else:
        boilerplate = (
            f'import django\n'
            f'os.environ.setdefault("{DJANGO_SETTINGS_MODULE}", "settings")\n'
            f'django.setup()\n\n'
        )
    new_source = INSTRUMENT_IMPORT_RE.sub(boilerplate + r"\1", source)
    if new_source == source:
        return boilerplate + source
    return new_source


FLASK_IMPORT_NAMES_RE = re.compile(
    r"from\s+\S+\s+import\s+(.*)"
)

FLASK_ASSIGN_RE = re.compile(r"(\w+)\s*=\s*Flask\s*\(")

FLASK_AS_RE = re.compile(r"\bapp\s+as\s+(\w+)\b")


def _find_flask_app_var(source: str) -> str | None:
    for match in FLASK_IMPORT_NAMES_RE.finditer(source):
        imported = match.group(1)
        as_match = FLASK_AS_RE.search(imported)
        if as_match:
            return as_match.group(1)
        if "app" in [name.strip() for name in imported.split(",")]:
            return "app"

    m2 = FLASK_ASSIGN_RE.search(source)
    if m2:
        return m2.group(1)

    return None


ENTRY_POINT_RE = re.compile(r"def\s+\w+\(data.*?\):")


def _wrap_in_flask_context(source: str, app_module: str) -> str:
    lines = source.split("\n")

    # Pass 1: find entry point function
    func_start = -1
    func_end = -1
    func_indent = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if ENTRY_POINT_RE.search(stripped):
            func_start = i
            func_indent = len(line) - len(stripped)
            break

    if func_start == -1:
        return source

    # Find func_end (next def or if __name__ at same or less indent)
    for i in range(func_start + 1, len(lines)):
        stripped = lines[i].strip()
        current_indent = len(lines[i]) - len(stripped)
        if (stripped.startswith("def ") or stripped.startswith("if __name__")) and current_indent <= func_indent:
            func_end = i
            break
    else:
        func_end = len(lines)

    # Pass 2: find try: within entry point
    try_start = -1
    for i in range(func_start, func_end):
        if lines[i].strip().startswith("try:"):
            try_start = i
            break

    if try_start == -1:
        return source

    try_indent = lines[try_start][: len(lines[try_start]) - len(lines[try_start].lstrip())]
    indent_unit = "\t" if try_indent.startswith("\t") else "    "

    if "request.args" in source and "request.form" not in source:
        wrapper = (
            f"{try_indent}{indent_unit}with {app_module}.test_request_context("
            f"\n{try_indent}{indent_unit * 2}query_string={{}}, method='GET'"
            f"\n{try_indent}{indent_unit}):"
        )
    else:
        wrapper = (
            f"{try_indent}{indent_unit}with {app_module}.test_request_context("
            f"\n{try_indent}{indent_unit * 2}data={{}}, method='POST'"
            f"\n{try_indent}{indent_unit}):"
        )

    result = list(lines[:try_start])
    result.append(wrapper)
    result.append(f"{try_indent}{indent_unit * 2}{lines[try_start].lstrip()}")

    for line in lines[try_start + 1 : func_end]:
        if line.strip():
            result.append(f"{indent_unit * 2}{line}")
        else:
            result.append(line)

    result.extend(lines[func_end:])

    return "\n".join(result)


def _inject_fastapi_setup(source: str) -> str:
    app_match = re.search(r"(\w+)\s*=\s*FastAPI\s*\(", source)
    if not app_match:
        return source
    app_var = app_match.group(1)

    import_stmt = f"from fastapi.testclient import TestClient\n\n"

    instrument_pos = source.find("with atheris.instrument_imports()")
    if instrument_pos != -1:
        before = source[:instrument_pos]
        after = source[instrument_pos:]
        source = before + import_stmt + after
    elif source.find("REPO_ROOT") != -1:
        repo_pos = source.find("REPO_ROOT")
        before = source[:repo_pos]
        after = source[repo_pos:]
        source = before + import_stmt + after
    else:
        source = import_stmt + source

    assign_stmt = f"{app_var}_client = TestClient({app_var})\n\n"
    repo_pos = source.rfind("REPO_ROOT")
    if repo_pos != -1:
        newline_pos = source.find("\n", repo_pos)
        if newline_pos != -1:
            before = source[:newline_pos + 1]
            after = source[newline_pos + 1:]
            return before + assign_stmt + after

    return source + assign_stmt


def fix_framework_context(source: str, repo_root: str = "") -> str:
    framework = _detect_framework(source, repo_root)

    if framework == "django":
        has_setup = "django.setup" in source or "DJANGO_SETTINGS_MODULE" in source
        if not has_setup:
            source = _inject_django_setup(source, repo_root)

    elif framework == "flask":
        app_module = _find_flask_app_var(source)
        if app_module:
            has_context = "test_request_context" in source
            if not has_context:
                source = _wrap_in_flask_context(source, app_module)

    elif framework == "fastapi":
        has_client = "TestClient" in source
        if not has_client:
            source = _inject_fastapi_setup(source)

    return source
