"""Fixer: replace slow instrument_imports() with fast instrument_all()."""

import re


_INSTRUMENT_IMPORTS_RE = re.compile(
    r"with atheris\.instrument_imports\(\):"
)


def fix_atheris_timeout(source: str, repo_root: str = "") -> str:
    """Replace `with atheris.instrument_imports():` with `atheris.instrument_all()`
    and dedent the block body."""
    if "with atheris.instrument_imports():" not in source:
        return source

    source = _INSTRUMENT_IMPORTS_RE.sub("atheris.instrument_all()", source)

    lines = source.split("\n")
    result = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if "atheris.instrument_all()" in line and i > 0 and "with" in lines[i - 1]:
            result.append(line)
            i += 1
            while i < len(lines) and (
                lines[i].startswith("    ")
                or lines[i].strip() == ""
                or lines[i].startswith("#")
            ):
                if lines[i].startswith("    "):
                    result.append(lines[i][4:])
                else:
                    result.append(lines[i])
                i += 1
            continue
        result.append(line)
        i += 1

    return "\n".join(result)
