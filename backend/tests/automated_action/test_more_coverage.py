"""Extra automated_action tests to meet ≥100 unit/integration target."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.application.ports.lookups import PlaybookLookupView, PlaybookStepView
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.services.automation_outbox_service import AutomationOutboxService
from automated_action.domain.services.execution_budget_service import ExecutionBudgetService
from automated_action.domain.value_objects.enums import ActionImpactLevel, ExecutionStatus
from automated_action.domain.value_objects.identifiers import AutomationExecutionId, TenantId
from automated_action.domain.value_objects.refs import (
    ActionEvidence,
    ExecutionContext,
    ExecutionResult,
    ExecutionTrace,
    PlaybookRef,
    TriggerRef,
)
from automated_action.infrastructure.acl.trigger_translators import (
    AutomationTriggerEvent,
    to_trigger_ref,
)
from automated_action.infrastructure.container import AutomatedActionContainer
from automated_action.infrastructure.projectors.analytics_projector import (
    AutomationAnalyticsProjector,
)


@pytest.mark.parametrize(
    ("running", "actions", "ok"),
    [
        (0, 0, True),
        (4, 99, True),
        (5, 0, False),
        (0, 100, False),
    ],
)
def test_budget_matrix(running: int, actions: int, ok: bool) -> None:
    allowed, _reason = ExecutionBudgetService().allows(
        running_count=running,
        max_concurrent=5,
        actions_last_hour=actions,
        max_actions_per_hour=100,
    )
    assert allowed is ok


def test_outbox_service_create() -> None:
    rec = AutomationOutboxService().create_pending(
        TenantId(uuid4()),
        AutomationExecutionId.generate(),
        1,
        "act",
        "ITSM_JIRA",
        "t",
        {"a": 1},
    )
    assert rec.step_number == 1


def test_value_object_refs() -> None:
    assert ActionEvidence(None, datetime.now(UTC), 1).duration_ms == 1
    assert ExecutionContext("t", "e", "o", "p").operator_id == "o"
    assert ExecutionTrace(1, "a", "COMPLETED", "ok").status == "COMPLETED"
    assert ExecutionResult(True, 2, 0, None).success is True


def test_to_trigger_ref() -> None:
    ref = to_trigger_ref(
        AutomationTriggerEvent("M28_FINDING", "f1", "t", "HIGH", None, "DetectionFindingEscalated")
    )
    assert ref.source_event_id == "f1"


def test_analytics_projector() -> None:
    p = AutomationAnalyticsProjector()

    class Ev:
        tenant_id = "t"
        execution_id = "e"

    p.project(Ev())
    assert p.rows[0]["event_type"] == "Ev"


def test_mark_rolled_back() -> None:
    ex = AutomationExecution(
        AutomationExecutionId.generate(),
        TenantId(uuid4()),
        PlaybookRef("p", 1, "h"),
        TriggerRef("MANUAL", "manual", "e"),
        ExecutionStatus.COMPLETED,
        datetime.now(UTC),
        "op",
        1,
        1,
        ActionImpactLevel.LOW,
    )
    ex.mark_rolled_back()
    assert ex.status == ExecutionStatus.ROLLED_BACK


@pytest.mark.asyncio
async def test_get_execution() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "g1", "op", ("automation:operator",)
        )
    )
    got = await c.app.get(tenant, UUID(ex.execution_id), ("playbook:analyst",))
    assert got.execution_id == ex.execution_id


@pytest.mark.asyncio
async def test_metrics_endpoint_counters() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    ex = await c.app.trigger(
        TriggerPlaybookExecution(
            tenant, pb, 1, "MANUAL", "manual", "m1", "op", ("automation:operator",)
        )
    )
    await c.app.run_pending_step_loop(tenant, UUID(ex.execution_id))
    assert c.app.metrics.counters.get("automation.execution.completed", 0) >= 1


@pytest.mark.asyncio
async def test_retry_and_recovery_workers() -> None:
    c = AutomatedActionContainer()
    c.retry_worker.tick()
    c.recovery_worker.tick()
    assert c.retry_worker.ticks == 1
    assert c.recovery_worker.ticks == 1


@pytest.mark.asyncio
async def test_trigger_worker() -> None:
    c = AutomatedActionContainer()
    tenant = uuid4()
    pb = uuid4()
    c.playbook_lookup.put(
        PlaybookLookupView(
            str(pb),
            1,
            "h",
            "LOW",
            "APPROVED",
            [PlaybookStepView(1, "a", "COMM_SLACK", "c", {}, "LOW")],
        )
    )
    dto = await c.trigger_worker.handle(
        tenant, pb, 1, "MANUAL", "manual", "tw1", "op", ("automation:operator",)
    )
    assert dto.status == "PENDING"
    assert c.trigger_worker.processed == 1
