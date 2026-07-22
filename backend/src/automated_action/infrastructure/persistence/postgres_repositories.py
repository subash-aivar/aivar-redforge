"""PostgreSQL repositories for automated_action.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across the other converted bounded contexts.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from automated_action.domain.aggregates.automated_action_record import AutomatedActionRecord
from automated_action.domain.aggregates.automation_execution import AutomationExecution
from automated_action.domain.aggregates.rollback_record import RollbackRecord
from automated_action.domain.entities.escalation_request import EscalationRequest
from automated_action.domain.repositories.i_automation_repositories import (
    IAutomatedActionRecordRepository,
    IAutomationExecutionRepository,
    IRollbackRecordRepository,
)
from automated_action.domain.value_objects.enums import (
    ActionImpactLevel,
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
    EscalationResolution,
    ExecutionStatus,
    RollbackStatus,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    RollbackRecordId,
    TenantId,
)
from automated_action.domain.value_objects.refs import PlaybookRef, TriggerRef
from automated_action.infrastructure.persistence.models.orm_models import (
    AutomatedActionRecordModel,
    AutomationExecutionModel,
    RollbackRecordModel,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


# ── AutomationExecution ─────────────────────────────────────────────────────


def _escalation_to_dict(esc: EscalationRequest) -> dict[str, object]:
    return {
        "escalation_id": str(esc.escalation_id),
        "step_number": esc.step_number,
        "impact_level": esc.impact_level.value,
        "required_role": esc.required_role,
        "trigger_operator_id": esc.trigger_operator_id,
        "escalated_at": esc.escalated_at.isoformat(),
        "expires_at": esc.expires_at.isoformat(),
        "authorized_by": esc.authorized_by,
        "authorized_at": esc.authorized_at.isoformat() if esc.authorized_at else None,
        "resolution": esc.resolution.value if esc.resolution else None,
    }


def _dict_to_escalation(d: dict[str, Any]) -> EscalationRequest:
    from datetime import datetime as _dt
    from uuid import UUID as _UUID

    authorized_by = d.get("authorized_by")
    return EscalationRequest(
        escalation_id=_UUID(str(d["escalation_id"])),
        step_number=int(d["step_number"]),
        impact_level=ActionImpactLevel(d["impact_level"]),
        required_role=str(d["required_role"]),
        trigger_operator_id=str(d["trigger_operator_id"]),
        escalated_at=_dt.fromisoformat(str(d["escalated_at"])),
        expires_at=_dt.fromisoformat(str(d["expires_at"])),
        authorized_by=str(authorized_by) if authorized_by is not None else None,
        authorized_at=(
            _dt.fromisoformat(str(d["authorized_at"])) if d.get("authorized_at") else None
        ),
        resolution=EscalationResolution(d["resolution"]) if d.get("resolution") else None,
    )


def _execution_to_row(execution: AutomationExecution) -> AutomationExecutionModel:
    from uuid import UUID as _UUID

    return AutomationExecutionModel(
        id=execution.execution_id.value,
        tenant_id=execution.tenant_id.value,
        playbook_id=_UUID(execution.playbook_ref.playbook_id),
        playbook_version=execution.playbook_ref.version_number,
        playbook_content_hash=execution.playbook_ref.version_content_hash,
        trigger_source_context=execution.trigger_ref.source_context,
        trigger_source_event_type=execution.trigger_ref.source_event_type,
        source_event_id=execution.trigger_ref.source_event_id,
        status=execution.status.value,
        operator_id=execution.operator_id,
        current_step=execution.current_step,
        total_steps=execution.total_steps,
        max_impact_level=execution.max_impact_level.value,
        escalation_request=(
            _escalation_to_dict(execution.escalation_request)
            if execution.escalation_request
            else None
        ),
        failure_reason=execution.failure_reason,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        created_at=execution.started_at,
        version=execution.version,
    )


def _row_to_execution(row: AutomationExecutionModel) -> AutomationExecution:
    return AutomationExecution(
        execution_id=AutomationExecutionId(row.id),
        tenant_id=TenantId(row.tenant_id),
        playbook_ref=PlaybookRef(
            playbook_id=str(row.playbook_id),
            version_number=row.playbook_version,
            version_content_hash=row.playbook_content_hash,
        ),
        trigger_ref=TriggerRef(
            source_context=row.trigger_source_context,
            source_event_type=row.trigger_source_event_type,
            source_event_id=row.source_event_id,
        ),
        status=ExecutionStatus(row.status),
        started_at=row.started_at,
        operator_id=row.operator_id,
        current_step=row.current_step,
        total_steps=row.total_steps,
        max_impact_level=ActionImpactLevel(row.max_impact_level),
        completed_at=row.completed_at,
        escalation_request=(
            _dict_to_escalation(row.escalation_request) if row.escalation_request else None
        ),
        failure_reason=row.failure_reason,
        version=row.version,
    )


class PgAutomationExecutionRepository(IAutomationExecutionRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, execution: AutomationExecution, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.merge(_execution_to_row(execution))
            await session.commit()

    async def get(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> AutomationExecution | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AutomationExecutionModel).where(
                        AutomationExecutionModel.tenant_id == tenant_id.value,
                        AutomationExecutionModel.id == execution_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_execution(row) if row is not None else None

    async def find_by_status(
        self, tenant_id: TenantId, status: ExecutionStatus, limit: int
    ) -> list[AutomationExecution]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AutomationExecutionModel)
                    .where(
                        AutomationExecutionModel.tenant_id == tenant_id.value,
                        AutomationExecutionModel.status == status.value,
                    )
                    .limit(limit)
                )
            ).scalars().all()
            return [_row_to_execution(r) for r in rows]

    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomationExecution]:
        from datetime import UTC, datetime, timedelta

        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AutomationExecutionModel).where(
                        AutomationExecutionModel.status == ExecutionStatus.PENDING.value,
                        AutomationExecutionModel.started_at < cutoff,
                    )
                )
            ).scalars().all()
            return [_row_to_execution(r) for r in rows]

    async def list(
        self,
        tenant_id: TenantId,
        *,
        status_filter: str | None,
        playbook_id_filter: str | None,
        page: int,
        page_size: int,
    ) -> list[AutomationExecution]:
        async with self._session_factory() as session:
            stmt = select(AutomationExecutionModel).where(
                AutomationExecutionModel.tenant_id == tenant_id.value
            )
            if status_filter:
                stmt = stmt.where(AutomationExecutionModel.status == status_filter)
            if playbook_id_filter:
                stmt = stmt.where(AutomationExecutionModel.playbook_id == playbook_id_filter)
            stmt = (
                stmt.order_by(AutomationExecutionModel.created_at)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
            rows = (await session.execute(stmt)).scalars().all()
            return [_row_to_execution(r) for r in rows]


# ── AutomatedActionRecord (append + targeted status update) ────────────────


def _record_to_row(
    record: AutomatedActionRecord, tenant_id: TenantId
) -> AutomatedActionRecordModel:
    return AutomatedActionRecordModel(
        id=record.record_id.value,
        tenant_id=tenant_id.value,
        execution_id=record.execution_id.value,
        step_number=record.step_number,
        action_type=record.action_type,
        connector_type=record.connector_type,
        target_resource=record.target_resource,
        parameters_hash=record.parameters_hash,
        status=record.status.value,
        outcome=record.outcome.value if record.outcome else None,
        external_reference=record.external_reference,
        failure_mode=record.failure_mode.value if record.failure_mode else None,
        attempted_at=record.attempted_at,
        completed_at=record.completed_at,
        duration_ms=record.duration_ms,
        rollback_available=record.rollback_available,
        rollback_parameters_ref=record.rollback_parameters_ref,
    )


def _row_to_record(row: AutomatedActionRecordModel) -> AutomatedActionRecord:
    return AutomatedActionRecord(
        record_id=AutomatedActionRecordId(row.id),
        tenant_id=TenantId(row.tenant_id),
        execution_id=AutomationExecutionId(row.execution_id),
        step_number=row.step_number,
        action_type=row.action_type,
        connector_type=row.connector_type,
        target_resource=row.target_resource,
        parameters_hash=row.parameters_hash,
        status=ActionRecordStatus(row.status),
        outcome=ActionOutcome(row.outcome) if row.outcome else None,
        external_reference=row.external_reference,
        failure_mode=ConnectorFailureMode(row.failure_mode) if row.failure_mode else None,
        attempted_at=row.attempted_at,
        completed_at=row.completed_at,
        duration_ms=row.duration_ms,
        rollback_available=row.rollback_available,
        rollback_parameters_ref=row.rollback_parameters_ref,
    )


class PgAutomatedActionRecordRepository(IAutomatedActionRecordRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(self, record: AutomatedActionRecord, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            session.add(_record_to_row(record, tenant_id))
            await session.commit()

    async def update_status(
        self,
        record_id: AutomatedActionRecordId,
        tenant_id: TenantId,
        status: ActionRecordStatus,
        outcome: ActionOutcome | None,
        external_reference: str | None,
        failure_mode: ConnectorFailureMode | None,
        completed_at: datetime,
        duration_ms: int,
    ) -> None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(AutomatedActionRecordModel).where(
                        AutomatedActionRecordModel.tenant_id == tenant_id.value,
                        AutomatedActionRecordModel.id == record_id.value,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return
            row.status = status.value
            row.outcome = outcome.value if outcome else None
            row.external_reference = external_reference
            row.failure_mode = failure_mode.value if failure_mode else None
            row.completed_at = completed_at
            row.duration_ms = duration_ms
            await session.commit()

    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[AutomatedActionRecord]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AutomatedActionRecordModel).where(
                        AutomatedActionRecordModel.tenant_id == tenant_id.value,
                        AutomatedActionRecordModel.execution_id == execution_id.value,
                    )
                )
            ).scalars().all()
            return [_row_to_record(r) for r in rows]

    async def find_pending_recovery(self, older_than_minutes: int) -> list[AutomatedActionRecord]:
        from datetime import UTC, datetime, timedelta

        cutoff = datetime.now(UTC) - timedelta(minutes=older_than_minutes)
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(AutomatedActionRecordModel).where(
                        AutomatedActionRecordModel.status == ActionRecordStatus.PENDING.value,
                        AutomatedActionRecordModel.attempted_at < cutoff,
                    )
                )
            ).scalars().all()
            return [_row_to_record(r) for r in rows]


# ── RollbackRecord (append + targeted status update) ────────────────────────


class PgRollbackRecordRepository(IRollbackRecordRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(self, record: RollbackRecord, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            session.add(
                RollbackRecordModel(
                    id=record.rollback_id.value,
                    tenant_id=tenant_id.value,
                    original_record_id=record.original_record_id.value,
                    execution_id=record.execution_id.value,
                    rollback_status=record.rollback_status.value,
                    initiated_by=record.initiated_by,
                    initiated_at=record.initiated_at,
                    completed_at=record.completed_at,
                    failure_reason=record.failure_reason,
                )
            )
            await session.commit()

    async def update_status(
        self,
        rollback_id: RollbackRecordId,
        tenant_id: TenantId,
        status: RollbackStatus,
        completed_at: datetime | None,
        failure_reason: str | None,
    ) -> None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(RollbackRecordModel).where(
                        RollbackRecordModel.tenant_id == tenant_id.value,
                        RollbackRecordModel.id == rollback_id.value,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return
            row.rollback_status = status.value
            row.completed_at = completed_at
            row.failure_reason = failure_reason
            await session.commit()

    async def find_by_execution(
        self, execution_id: AutomationExecutionId, tenant_id: TenantId
    ) -> list[RollbackRecord]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(RollbackRecordModel).where(
                        RollbackRecordModel.tenant_id == tenant_id.value,
                        RollbackRecordModel.execution_id == execution_id.value,
                    )
                )
            ).scalars().all()
            return [
                RollbackRecord(
                    rollback_id=RollbackRecordId(r.id),
                    tenant_id=TenantId(r.tenant_id),
                    original_record_id=AutomatedActionRecordId(r.original_record_id),
                    execution_id=AutomationExecutionId(r.execution_id),
                    rollback_status=RollbackStatus(r.rollback_status),
                    initiated_by=r.initiated_by,
                    initiated_at=r.initiated_at,
                    completed_at=r.completed_at,
                    failure_reason=r.failure_reason,
                )
                for r in rows
            ]
