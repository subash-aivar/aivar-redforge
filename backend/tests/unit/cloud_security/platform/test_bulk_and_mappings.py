"""Bulk helpers and ORM mapping unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from ulid import ULID

from redforge.application.cloud_security.platform.bulk import (
    BatchOrchestrationPlan,
    chunk_ids,
    merge_diagnostics,
    paginate_offset,
)
from redforge.domain.cloud_security.platform.entities import (
    OrchestrationRun,
    OrchestrationStepResult,
)
from redforge.domain.cloud_security.platform.value_objects import (
    OrchestrationScope,
    StepName,
    StepStatus,
)
from redforge.domain.cloud_security.value_objects import OrganizationId
from redforge.infrastructure.cloud_security.platform.mappings import (
    run_from_model,
    run_to_model,
)
from redforge.infrastructure.database.models.cloud_security import CloudOrchestrationRunModel

NOW = datetime(2026, 7, 20, 10, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("page", "size", "expected"),
    [
        (1, 50, (50, 0)),
        (2, 50, (50, 50)),
        (0, 10, (10, 0)),
        (3, 200, (200, 400)),
        (1, 999, (200, 0)),
        (5, 25, (25, 100)),
    ],
)
def test_paginate_offset(page: int, size: int, expected: tuple[int, int]) -> None:
    assert paginate_offset(page=page, size=size) == expected


@pytest.mark.parametrize("n", [0, 1, 10, 25, 26, 50, 99])
def test_chunk_ids(n: int) -> None:
    ids = [uuid4() for _ in range(n)]
    chunks = chunk_ids(ids, chunk_size=25)
    flat = [i for c in chunks for i in c]
    assert flat == ids
    assert all(len(c) <= 25 for c in chunks)


@pytest.mark.parametrize(
    "parts",
    [
        ({"a": 1}, {"b": 2}),
        ({"a": 1}, {"a": 2}),
        ({}, {"x": True}),
        ({"op": "1"}, {"step": "x"}, {"ms": 3}),
    ],
)
def test_merge_diagnostics(parts: tuple[dict[str, object], ...]) -> None:
    merged = merge_diagnostics(*parts)
    for part in parts:
        for key in part:
            assert key in merged


@pytest.mark.parametrize("count", range(1, 12))
def test_batch_plan(count: int) -> None:
    plan = BatchOrchestrationPlan(
        organization_id="org",
        account_ids=tuple(uuid4() for _ in range(count)),
        fail_fast=False,
    )
    assert plan.batch_size == count


@pytest.mark.parametrize("scope", list(OrchestrationScope))
def test_run_mapping_roundtrip(scope: OrchestrationScope) -> None:
    org = OrganizationId(str(ULID()))
    run = OrchestrationRun.start(
        organization_id=org,
        scope=scope,
        target_id="target-1",
        operation_id="op_map",
        correlation_id="c1",
        request_id="r1",
        now=NOW,
    )
    run.record_step(
        OrchestrationStepResult(
            step_name=StepName.DISCOVER_ASSETS,
            status=StepStatus.COMPLETED,
            started_at=NOW,
            completed_at=NOW,
            duration_ms=1.5,
            message="ok",
            details={"n": 1},
        )
    )
    run.complete(now=NOW)
    model = run_to_model(run)
    assert isinstance(model, CloudOrchestrationRunModel)
    restored = run_from_model(model)
    assert str(restored.id) == str(run.id)
    assert restored.scope is scope
    assert restored.organization_id == org
    assert len(restored.steps) == 1
    assert restored.steps[0].step_name is StepName.DISCOVER_ASSETS
    assert restored.operation_id == "op_map"
