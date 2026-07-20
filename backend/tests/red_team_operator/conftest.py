"""Shared fixtures for RedTeamOperator tests."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from red_team_operator.domain.aggregates.red_team_operator import RedTeamOperator
from red_team_operator.domain.value_objects.enums import (
    ApprovalScope,
    OperatorClearanceLevel,
)
from red_team_operator.domain.value_objects.identifiers import OperatorId, TenantId


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
def other_tenant_id() -> TenantId:
    return TenantId(uuid4())


def advance(now: datetime, **kwargs: int) -> datetime:
    return now + timedelta(**kwargs)


def make_operator(
    *,
    tenant_id: TenantId,
    now: datetime,
    identity_ref: str = "alice@aivar.io",
    clearance: OperatorClearanceLevel = OperatorClearanceLevel.L3,
    scopes: list[ApprovalScope] | None = None,
    operator_id: OperatorId | None = None,
    pop_events: bool = False,
) -> RedTeamOperator:
    default_scopes = scopes
    if default_scopes is None and clearance in {
        OperatorClearanceLevel.L3,
        OperatorClearanceLevel.L4_CISO,
    }:
        default_scopes = [ApprovalScope.ENGAGEMENT_APPROVAL, ApprovalScope.OPERATION_APPROVAL]
    elif default_scopes is None:
        default_scopes = []

    op = RedTeamOperator.activate(
        tenant_id=tenant_id,
        identity_ref=identity_ref,
        clearance_level=clearance,
        now=now,
        display_name=identity_ref.split("@")[0],
        approval_scopes=default_scopes,
        operator_id=operator_id,
    )
    if pop_events:
        op.pop_events()
    return op
