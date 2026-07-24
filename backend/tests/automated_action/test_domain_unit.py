from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.services.automation_authorization_service import (
    AutomationAuthorizationService,
)
from automated_action.domain.services.execution_budget_service import ExecutionBudgetService
from automated_action.domain.services.execution_recovery_service import ExecutionRecoveryService
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    ActionRecordStatus,
    ConnectorFailureMode,
    ExecutionStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomationExecutionId,
    TenantId,
)


@pytest.mark.parametrize("level", list(ActionImpactLevel))
def test_impact(level: ActionImpactLevel) -> None:
    assert level.value == level.name


@pytest.mark.parametrize("status", list(ExecutionStatus))
def test_exec_status(status: ExecutionStatus) -> None:
    assert status.value == status.name


@pytest.mark.parametrize("mode", list(ConnectorFailureMode))
def test_failure_mode(mode: ConnectorFailureMode) -> None:
    assert mode.value == mode.name


def test_budget() -> None:
    ok, reason = ExecutionBudgetService().allows(
        running_count=5, max_concurrent=5, actions_last_hour=1, max_actions_per_hour=100
    )
    assert ok is False
    assert reason == "max_concurrent_executions"


def test_recovery_stale() -> None:
    rec = AutomatedActionRecord.create_pending(
        TenantId.generate(),
        AutomationExecutionId.generate(),
        1,
        "a",
        "COMM_SLACK",
        "t",
        {},
    )
    rec.attempted_at = datetime.now(UTC) - timedelta(minutes=6)
    assert ExecutionRecoveryService().is_stale(rec) is True
    assert rec.status == ActionRecordStatus.PENDING


def test_runtime_auth_low() -> None:
    AutomationAuthorizationService().assert_runtime_authorized(ActionImpactLevel.LOW, (), "a", "b")
