"""Validate mock construction JSON output against the YAML specification."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

VALID_Q2_OWNERS = {"built-in", "imported module", "class method"}
VALID_CALL_STYLES = {"standalone", "context_manager", "chained", "standalone_with_close", "return_value"}
VALID_MOCK_TYPES = {"standalone", "context_manager", "chained"}
VALID_ARG_PASSING = {"positional", "keyword"}
VALID_RETURN_SPECS = {"str", "dict", "list", "file", "response", "object"}
VALID_INPUT_SOURCES = {"django_view", "flask_view", "direct_call"}
VALID_INPUT_METHODS = {
    "post_form", "get_query", "form", "query", "header", "cookie", "path", "direct_call",
}
VALID_CALL_COUNTS = {"single", "multiple"}
VALID_CONFIDENCE = {"high", "medium", "low"}


class MockConstructionValidationError(ValueError):
    """Raised when mock construction JSON fails validation."""


def _load_spec() -> dict[str, Any]:
    """Load the mock construction YAML specification."""
    search_roots = [
        Path(__file__).resolve().parents[3],  # src/oraculum/mock_analysis -> project root
        Path.cwd(),
    ]
    for root in search_roots:
        candidate = root / "docs" / "plan" / "issue" / "mock_construction_questions.yaml"
        if candidate.is_file():
            with candidate.open(encoding="utf-8") as f:
                return yaml.safe_load(f)
    raise FileNotFoundError(
        "mock_construction_questions.yaml not found in any search root"
    )


def validate_mock_construction(result: dict[str, Any]) -> list[str]:
    """Validate a mock construction result against the YAML spec.

    Returns a list of error/warning strings. Empty means valid.
    Raises MockConstructionValidationError if critical errors exist.
    """
    spec = _load_spec()
    errors: list[str] = []

    # 1. Required fields
    required = spec["output_contract"]["required_fields"]
    missing = [f for f in required if f not in result]
    if missing:
        errors.append(f"missing required fields: {', '.join(missing)}")

    # 2. Enum validation
    enums = spec["output_contract"]["enums"]
    for field, valid_values in enums.items():
        actual = result.get(field)
        if actual is None and "null" in valid_values:
            continue
        if actual is not None and actual not in valid_values:
            errors.append(
                f"{field}: invalid value {actual!r}, "
                f"expected one of {valid_values}"
            )

    # 3. Validation rules
    call_style = result.get("q3_call_style", "")
    call_style_null_fields = [
        "q1_sink_name", "q2_sink_owner", "q2_prefix", "q2_fqn",
        "q4_arg_passing", "q4_arg_index", "q4_arg_name",
        "q5_return_used", "q5_mock_return_spec", "q5_context_var",
        "q8_call_count", "q8_tainted_call_index",
    ]

    if call_style == "return_value":
        for f in call_style_null_fields:
            val = result.get(f)
            if val is not None and (not isinstance(val, list) or val):
                errors.append(
                    f"{f} must be null or [] when call_style is return_value, "
                    f"got {val!r}"
                )
    elif call_style != "return_value":
        if not result.get("q2_fqn"):
            errors.append("q2_fqn must be non-empty when call_style is not return_value")

    arg_passing = result.get("q4_arg_passing")
    if arg_passing == "positional":
        if result.get("q4_arg_index") is None:
            errors.append("q4_arg_index must be int when arg_passing is positional")
        if result.get("q4_arg_name") is not None:
            errors.append("q4_arg_name must be null when arg_passing is positional")
    elif arg_passing == "keyword":
        if not result.get("q4_arg_name"):
            errors.append("q4_arg_name must be non-empty when arg_passing is keyword")
        if result.get("q4_arg_index") is not None:
            errors.append("q4_arg_index must be null when arg_passing is keyword")

    if call_style == "chained":
        if not result.get("q3_chained_method"):
            errors.append("q3_chained_method must be non-empty when call_style is chained")
        if result.get("q3_chained_depth", 0) <= 0:
            errors.append("q3_chained_depth must be > 0 when call_style is chained")

    if call_style == "standalone_with_close":
        if result.get("q3_mock_type") != "standalone":
            errors.append("q3_mock_type must be standalone for standalone_with_close")
        if "close" not in result.get("q5_methods_called", []):
            errors.append(
                "q5_methods_called should include 'close' for standalone_with_close"
            )

    if not isinstance(result.get("q5_methods_called"), list):
        errors.append("q5_methods_called must be a list")
    if not isinstance(result.get("warnings"), list):
        errors.append("warnings must be a list of strings")
    if not isinstance(result.get("q3_chained_depth", 0), int):
        errors.append("q3_chained_depth must be a non-negative integer")

    # Auto-warnings from spec
    for trigger in spec.get("warning_triggers", []):
        condition = trigger["condition"]
        warning = trigger["warning"]
        if (
            "q5_mock_return_spec is" in condition
            and result.get("q5_mock_return_spec") == "object"
            and not result.get("q5_methods_called")
        ):
            if warning not in result.get("warnings", []):
                result.setdefault("warnings", []).append(warning)

    if errors:
        raise MockConstructionValidationError("; ".join(errors))
    return errors
