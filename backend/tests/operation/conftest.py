"""Shared fixtures for Operation domain and unit tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from operation.domain.aggregates.operation import Operation
from operation.domain.value_objects.enums import (
    ImpactCeiling,
    OperationClassification,
    StepType,
)
from operation.domain.value_objects.identifiers import EngagementId, OperationId, TenantId
from operation.domain.value_objects.plan_vos import (
    StepConstraints,
    StepTargetRef,
    StepTechniqueRef,
)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: marks tests requiring PostgreSQL",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if os.environ.get("TEST_DATABASE_URL"):
        return
    skip_integration = pytest.mark.skip(
        reason="TEST_DATABASE_URL not set — skipping integration tests"
    )
    for item in items:
        if "integration" in item.keywords:
            item.add_marker(skip_integration)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 7, 20, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId(uuid4())


@pytest.fixture
def engagement_id() -> EngagementId:
    return EngagementId(uuid4())


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)


def default_constraints() -> StepConstraints:
    return StepConstraints(
        max_duration_seconds=300,
        rollback_on_failure=True,
        continue_on_failure=False,
    )


def make_operation(
    *,
    tenant_id: TenantId,
    now: datetime,
    engagement_id: EngagementId | None = None,
    name: str = "Initial Access Op",
    classification: OperationClassification = OperationClassification.INITIAL_ACCESS,
    operation_id: OperationId | None = None,
    pop_events: bool = False,
) -> Operation:
    op = Operation.create(
        tenant_id=tenant_id,
        engagement_id=engagement_id or EngagementId(uuid4()),
        name=name,
        classification=classification,
        now=now,
        operation_id=operation_id,
    )
    if pop_events:
        op.pop_events()
    return op


def add_attack_step(
    op: Operation,
    *,
    tenant_id: TenantId,
    now: datetime,
    name: str = "attack",
    impact: ImpactCeiling | None = ImpactCeiling.PROBE,
    technique_id: str | None = "T1059",
    target_asset_id=None,
    modifies_persistent_state: bool = False,
) -> object:
    return op.add_execution_step(
        tenant_id=tenant_id,
        name=name,
        step_type=StepType.ATTACK_STEP,
        constraints=default_constraints(),
        now=now,
        technique_ref=(
            StepTechniqueRef(payload_id="payload-1", technique_id=technique_id)
            if technique_id
            else None
        ),
        target_ref=(
            StepTargetRef(asset_id=target_asset_id) if target_asset_id is not None else None
        ),
        impact_ceiling=impact,
        modifies_persistent_state=modifies_persistent_state,
    )


def add_gate_step(op: Operation, *, tenant_id: TenantId, now: datetime, name: str = "gate"):
    return op.add_execution_step(
        tenant_id=tenant_id,
        name=name,
        step_type=StepType.HUMAN_APPROVAL_GATE,
        constraints=default_constraints(),
        now=now,
    )


def add_verification_step(
    op: Operation, *, tenant_id: TenantId, now: datetime, name: str = "verify"
):
    return op.add_execution_step(
        tenant_id=tenant_id,
        name=name,
        step_type=StepType.VERIFICATION_STEP,
        constraints=default_constraints(),
        now=now,
    )
