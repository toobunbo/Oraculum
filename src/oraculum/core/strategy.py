"""Shared strategy validation for Oraculum pipeline stages."""


VALID_STRATEGIES = {"return_value", "recorded_call", "filesystem_state"}


def validate_strategy(strategy: str) -> None:
    """Raise ValueError when a pipeline strategy is unknown."""
    if strategy not in VALID_STRATEGIES:
        raise ValueError(f"unknown strategy: {strategy!r}")


def validate_readme_strategy(strategy: str) -> None:
    """Backward-compatible alias for strategy validation."""
    validate_strategy(strategy)


def validate_monitor_strategy(monitor: str) -> None:
    """Backward-compatible alias for strategy validation."""
    validate_strategy(monitor)
