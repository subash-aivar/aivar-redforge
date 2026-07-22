"""Integration tests for automated_action's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    ActionOutcome,
    ActionRecordStatus,
    ExecutionStatus,
    RollbackStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    TenantId,
)
from automated_action.domain.value_objects.refs import PlaybookRef, TriggerRef
from automated_action.infrastructure.persistence.postgres_repositories import (
    PgAutomatedActionRecordRepository,
    PgAutomationExecutionRepository,
    PgRollbackRecordRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_execution_lifecycle_with_escalation(session_factory) -> None:
    repo = PgAutomationExecutionRepository(session_factory)
    tenant_id = TenantId(uuid7())

    execution = AutomationExecution.create(
        tenant_id,
        PlaybookRef(playbook_id=str(uuid7()), version_number=1, version_content_hash="hash1"),
        TriggerRef(source_context="M34_INCIDENT", source_event_type="malware", source_event_id="evt-1"),
        "operator-1",
        total_steps=3,
        max_impact_level=ActionImpactLevel.HIGH,
    )
    execution.start()
    await repo.save(execution, tenant_id)

    execution.escalate(2, ActionImpactLevel.HIGH, "soc:lead")
    await repo.save(execution, tenant_id)

    fetched = await repo.get(execution.execution_id, tenant_id)
    assert fetched is not None
    assert fetched.status.value == "AWAITING_AUTHORIZATION"
    assert fetched.escalation_request is not None
    assert fetched.escalation_request.required_role == "soc:lead"
    assert fetched.trigger_ref.source_event_type == "malware"

    fetched.authorize_step(str(fetched.escalation_request.escalation_id), "manager-1")
    fetched.complete(steps_completed=3)
    await repo.save(fetched, tenant_id)

    completed = await repo.find_by_status(tenant_id, ExecutionStatus.COMPLETED, limit=10)
    assert any(str(e.execution_id) == str(execution.execution_id) for e in completed)

    listed = await repo.list(
        tenant_id, status_filter=None, playbook_id_filter=None, page=1, page_size=10
    )
    assert len(listed) == 1


@pytest.mark.asyncio
async def test_pending_execution_recovery_scan(session_factory) -> None:
    repo = PgAutomationExecutionRepository(session_factory)
    tenant_id = TenantId(uuid7())

    stale = AutomationExecution(
        execution_id=AutomationExecutionId.generate(),
        tenant_id=tenant_id,
        playbook_ref=PlaybookRef(playbook_id=str(uuid7()), version_number=1, version_content_hash="h"),
        trigger_ref=TriggerRef(source_context="MANUAL", source_event_type="manual", source_event_id="e2"),
        status=ExecutionStatus.PENDING,
        started_at=datetime.now(UTC) - timedelta(minutes=90),
        operator_id="operator-1",
        current_step=0,
        total_steps=1,
        max_impact_level=ActionImpactLevel.LOW,
    )
    await repo.save(stale, tenant_id)

    pending = await repo.find_pending_recovery(older_than_minutes=60)
    assert any(str(e.execution_id) == str(stale.execution_id) for e in pending)


@pytest.mark.asyncio
async def test_action_record_append_and_update_status(session_factory) -> None:
    repo = PgAutomatedActionRecordRepository(session_factory)
    tenant_id = TenantId(uuid7())
    execution_id = uuid7()

    record = AutomatedActionRecord.create_pending(
        tenant_id,
        AutomationExecutionId(execution_id),
        1,
        "isolate_host",
        "EDR_CROWDSTRIKE",
        "host-42",
        {"scope": "network"},
    )
    await repo.append(record, tenant_id)

    await repo.update_status(
        record.record_id,
        tenant_id,
        ActionRecordStatus.COMPLETED,
        ActionOutcome.SUCCESS,
        "ext-ref-1",
        None,
        datetime.now(UTC),
        1500,
    )

    by_execution = await repo.find_by_execution(AutomationExecutionId(execution_id), tenant_id)
    assert len(by_execution) == 1
    assert by_execution[0].status.value == "COMPLETED"
    assert by_execution[0].external_reference == "ext-ref-1"


@pytest.mark.asyncio
async def test_rollback_record_append_and_update_status(session_factory) -> None:
    repo = PgRollbackRecordRepository(session_factory)
    tenant_id = TenantId(uuid7())
    execution_id = AutomationExecutionId.generate()
    rollback = RollbackRecord.create(
        tenant_id, AutomatedActionRecordId.generate(), execution_id, "operator-1"
    )
    await repo.append(rollback, tenant_id)

    await repo.update_status(rollback.rollback_id, tenant_id, RollbackStatus.COMPLETED, datetime.now(UTC), None)

    by_execution = await repo.find_by_execution(execution_id, tenant_id)
    assert len(by_execution) == 1
    assert by_execution[0].rollback_status.value == "COMPLETED"
