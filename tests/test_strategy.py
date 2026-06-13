from __future__ import annotations

import pytest

from oraculum.core.strategy import (
    VALID_STRATEGIES,
    validate_monitor_strategy,
    validate_readme_strategy,
    validate_strategy,
)


def test_valid_strategies_are_pipeline_contract() -> None:
    assert {"return_value", "recorded_call", "filesystem_state"} == VALID_STRATEGIES
    for strategy in VALID_STRATEGIES:
        validate_strategy(strategy)


def test_invalid_readme_strategy_raises() -> None:
    with pytest.raises(ValueError, match="unknown strategy"):
        validate_readme_strategy("unknown_strategy")


def test_invalid_monitor_strategy_raises() -> None:
    with pytest.raises(ValueError, match="unknown strategy"):
        validate_monitor_strategy("unknown_strategy")
