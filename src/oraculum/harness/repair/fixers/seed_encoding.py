import re


SEED_WRITE_PATTERN = re.compile(
    r"(\s+with open\((\w+), [\"']wb[\"']\) as (\w+):)\n(?:\s*\n)*(\s+)\3\.write\((\w+)\.encode\([\"']utf-8[\"']\)\)"
)


def _seed_replace(m: re.Match) -> str:
    with_indent = m.group(1)
    f_var = m.group(3)
    body_indent = m.group(4)
    seed_var = m.group(5)
    indent_unit = "\t" if body_indent.startswith("\t") else "    "
    stmt_indent = body_indent
    inner_indent = body_indent + indent_unit
    return (
        f"{with_indent}\n"
        f"{stmt_indent}if isinstance({seed_var}, bytes):\n"
        f"{inner_indent}{f_var}.write({seed_var})\n"
        f"{stmt_indent}else:\n"
        f"{inner_indent}{f_var}.write({seed_var}.encode(\"utf-8\"))"
    )


def fix_seed_encoding(source: str, repo_root: str = "") -> str:
    return SEED_WRITE_PATTERN.sub(_seed_replace, source)
