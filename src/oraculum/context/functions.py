"""Load function context rows and map findings to enclosing functions."""

from __future__ import annotations

import csv
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

REQUIRED_FUNCTION_COLUMNS = {"name", "file", "start_line", "end_line"}


class FunctionsCsvError(ValueError):
    """Raised when functions.csv is missing or malformed."""


@dataclass(frozen=True)
class FunctionInfo:
    """A function row from VulnHunterX context/functions.csv."""

    name: str
    file: str
    start_line: int
    end_line: int
    scope: str = ""

    @property
    def span(self) -> int:
        return self.end_line - self.start_line

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def load_functions_csv(path: Path) -> list[FunctionInfo]:
    """Load VulnHunterX context/functions.csv."""
    if not path.is_file():
        raise FunctionsCsvError(f"functions.csv not found: {path}")

    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = set(reader.fieldnames or [])
            missing = REQUIRED_FUNCTION_COLUMNS - fieldnames
            if missing:
                missing_list = ", ".join(sorted(missing))
                raise FunctionsCsvError(f"functions.csv missing columns ({missing_list}): {path}")

            rows: list[FunctionInfo] = []
            for line_number, row in enumerate(reader, start=2):
                try:
                    start = int(row.get("start_line", ""))
                    end = int(row.get("end_line", ""))
                except ValueError as exc:
                    raise FunctionsCsvError(
                        f"Invalid function line range at {path}:{line_number}"
                    ) from exc

                rows.append(
                    FunctionInfo(
                        name=row.get("name", ""),
                        file=row.get("file", ""),
                        start_line=start,
                        end_line=end,
                        scope=row.get("scope", ""),
                    )
                )
    except OSError as exc:
        raise FunctionsCsvError(f"Could not read functions.csv: {path}: {exc}") from exc

    return rows


def find_enclosing_function(
    functions: list[FunctionInfo],
    file_path: str,
    start_line: int,
) -> FunctionInfo | None:
    """Find the narrowest function enclosing file_path:start_line."""
    matches = [
        func
        for func in functions
        if func.file == file_path and func.start_line <= start_line <= func.end_line
    ]
    if not matches:
        return None
    return min(matches, key=lambda func: (func.span, func.start_line, func.name))

