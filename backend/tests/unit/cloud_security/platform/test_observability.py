"""Observability helper tests."""

from __future__ import annotations

import pytest

from redforge.application.cloud_security.platform.observability import (
    bind_run_context,
    new_operation_id,
    step_timer,
)


@pytest.mark.parametrize("n", range(20))
def test_operation_ids_unique_prefix(n: int) -> None:
    op = new_operation_id()
    assert op.startswith("op_")
    assert len(op) == 19


def test_operation_ids_differ() -> None:
    assert new_operation_id() != new_operation_id()


@pytest.mark.parametrize(
    ("kwargs", "keys"),
    [
        ({"organization_id": "o1", "operation_id": "op1"}, {"organization_id", "operation_id"}),
        (
            {
                "organization_id": "o1",
                "operation_id": "op1",
                "run_id": "r1",
                "correlation_id": "c1",
                "request_id": "q1",
                "step": "DISCOVER_ASSETS",
            },
            {
                "organization_id",
                "operation_id",
                "run_id",
                "correlation_id",
                "request_id",
                "step",
            },
        ),
    ],
)
def test_bind_run_context(kwargs: dict[str, str], keys: set[str]) -> None:
    ctx = bind_run_context(**kwargs)
    assert set(ctx.keys()) == keys
    assert "credential" not in str(ctx).lower()
    assert "secret" not in str(ctx).lower()


@pytest.mark.parametrize("step", ["DISCOVER_ASSETS", "EVALUATE_CSPM", "CALCULATE_RISK"])
def test_step_timer(step: str) -> None:
    with step_timer(step) as meta:
        assert meta["step_name"] == step
        _ = sum(range(1000))
    assert meta["duration_ms"] >= 0.0


@pytest.mark.parametrize("i", range(15))
def test_step_timer_records_duration(i: int) -> None:
    with step_timer(f"STEP_{i}") as meta:
        pass
    assert "duration_ms" in meta
