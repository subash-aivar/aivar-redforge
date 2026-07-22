"""Additional playbook unit coverage for M35 phase exit criteria."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from playbook.domain.aggregates.automation_policy import AutomationPolicy
from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidPlaybookTransition,
    KillSwitchActive,
    VersionImmutableError,
)
from playbook.domain.services.kill_switch_service import KillSwitchService
from playbook.domain.services.playbook_approval_service import PlaybookApprovalService
from playbook.domain.services.playbook_lifecycle_service import PlaybookLifecycleService
from playbook.domain.value_objects.definitions import (
    ActionStepDefinition,
    RollbackDefinition,
    TargetSelectorExpression,
    TriggerCondition,
)
from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    KillSwitchState,
    PlaybookStatus,
    TriggerSourceContext,
)
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookTestResultId,
    PlaybookVersionId,
    TenantId,
)
from playbook.infrastructure.container import PlaybookContainer


@pytest.mark.parametrize(
    ("level", "quorum"),
    [
        (ActionImpactLevel.LOW, 1),
        (ActionImpactLevel.MEDIUM, 1),
        (ActionImpactLevel.HIGH, 2),
        (ActionImpactLevel.CRITICAL, 2),
    ],
)
def test_approval_quorum(level: ActionImpactLevel, quorum: int) -> None:
    assert PlaybookApprovalService().quorum_for(level) == quorum


@pytest.mark.parametrize(
    ("steps", "expected"),
    [
        ([], ActionImpactLevel.LOW),
        (
            [
                ActionStepDefinition(
                    1,
                    "a",
                    ConnectorType.COMM_SLACK,
                    TargetSelectorExpression("*"),
                    {},
                    ActionImpactLevel.MEDIUM,
                )
            ],
            ActionImpactLevel.MEDIUM,
        ),
        (
            [
                ActionStepDefinition(
                    1,
                    "a",
                    ConnectorType.EDR_CROWDSTRIKE,
                    TargetSelectorExpression("*"),
                    {},
                    ActionImpactLevel.LOW,
                ),
                ActionStepDefinition(
                    2,
                    "b",
                    ConnectorType.EDR_CROWDSTRIKE,
                    TargetSelectorExpression("*"),
                    {},
                    ActionImpactLevel.CRITICAL,
                ),
            ],
            ActionImpactLevel.CRITICAL,
        ),
    ],
)
def test_lifecycle_max_impact(
    steps: list[ActionStepDefinition], expected: ActionImpactLevel
) -> None:
    assert PlaybookLifecycleService().max_impact(steps) == expected


def test_playbook_create_emits_event() -> None:
    pb = Playbook.create(TenantId(uuid4()), "n", "d", "u1")
    events = pb.pop_events()
    assert pb.status == PlaybookStatus.DRAFT
    assert len(events) == 1


def test_submit_requires_version() -> None:
    pb = Playbook.create(TenantId(uuid4()), "n", "d", "u1")
    with pytest.raises(DomainInvariantViolation):
        pb.submit_for_approval(pb.tenant_id)


def test_deprecate_twice_fails() -> None:
    pb = Playbook.create(TenantId(uuid4()), "n", "d", "u1")
    pb.deprecate(pb.tenant_id, "u", "r")
    with pytest.raises(InvalidPlaybookTransition):
        pb.deprecate(pb.tenant_id, "u", "r2")


def test_version_immutable_after_publish() -> None:
    v = PlaybookVersion.create_draft(
        TenantId(uuid4()),
        PlaybookId.generate(),
        1,
        [
            ActionStepDefinition(
                1,
                "a",
                ConnectorType.ITSM_JIRA,
                TargetSelectorExpression("*"),
                {"p": 1},
                ActionImpactLevel.LOW,
            )
        ],
        [TriggerCondition(TriggerSourceContext.MANUAL, "manual")],
    )
    v.publish("eng")
    with pytest.raises(VersionImmutableError):
        v.publish("eng2")


def test_policy_budgets_bounds() -> None:
    p = AutomationPolicy.default(TenantId(uuid4()))
    with pytest.raises(DomainInvariantViolation):
        p.update_budgets(max_concurrent_executions=0)
    with pytest.raises(DomainInvariantViolation):
        p.update_budgets(max_actions_per_hour=1001)
    p.update_budgets(max_concurrent_executions=10, max_actions_per_hour=200)
    assert p.max_concurrent_executions == 10


def test_kill_switch_service() -> None:
    p = AutomationPolicy.default(TenantId(uuid4()))
    svc = KillSwitchService()
    assert svc.is_triggered(p) is False
    svc.activate(p, "ciso", "stop")
    assert svc.is_triggered(p) is True
    assert p.kill_switch_state == KillSwitchState.TRIGGERED
    with pytest.raises(KillSwitchActive):
        p.assert_armed()
    svc.reset(p, "ciso")
    assert svc.is_triggered(p) is False


def test_test_result_ids() -> None:
    tid = PlaybookTestResultId.generate()
    assert str(tid)
    assert PlaybookVersionId.generate()
    assert PlaybookId.generate()


def test_rollback_definition() -> None:
    rb = RollbackDefinition("undo", ConnectorType.EDR_DEFENDER, True, 12)
    assert rb.max_rollback_window_hours == 12


@pytest.mark.asyncio
async def test_container_list_empty() -> None:
    c = PlaybookContainer()
    rows = await c.app.list_playbooks(uuid4(), ("playbook:analyst",))
    assert rows == []


@pytest.mark.asyncio
async def test_scheduler_ticks() -> None:
    c = PlaybookContainer()
    result = c.scheduler.tick_all()
    assert result["metrics_ticks"] == 1


def test_playbook_test_result_factory() -> None:
    result = PlaybookTestResult.create(
        TenantId(uuid4()),
        PlaybookId.generate(),
        PlaybookVersionId.generate(),
        "abc",
        __import__(
            "playbook.domain.value_objects.enums", fromlist=["TestOutcome"]
        ).TestOutcome.PASSED,
        1,
        1,
        ["step:1:ok"],
        "eng",
        datetime.now(UTC),
        10,
    )
    assert result.steps_passed == 1
