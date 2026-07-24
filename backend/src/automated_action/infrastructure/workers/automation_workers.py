from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from automated_action.application.commands.automation_commands import TriggerPlaybookExecution
from automated_action.domain.value_objects.enums import ActionRecordStatus, ExecutionStatus
from automated_action.domain.value_objects.identifiers import TenantId


class PlaybookTriggerWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def handle(
        self,
        tenant_id: TenantId,
        playbook_id: UUID,
        version_number: int,
        source_context: str,
        source_event_type: str,
        source_event_id: str,
        operator_id: str,
        roles: tuple[str, ...],
    ) -> Any:
        self.processed += 1
        return await self._app.trigger(
            TriggerPlaybookExecution(
                tenant_id,
                playbook_id,
                version_number,
                source_context,
                source_event_type,
                source_event_id,
                operator_id,
                roles,
            )
        )


class PlaybookExecutionWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def process(self, tenant_id: TenantId, execution_id: UUID) -> Any:
        self.processed += 1
        return await self._app.run_pending_step_loop(tenant_id, execution_id)


class EscalationTimeoutWorker:
    def __init__(self, executions: Any) -> None:
        self._executions = executions
        self.expired = 0

    async def tick(self, tenant_id: TenantId) -> int:

        rows = await self._executions.find_by_status(
            tenant_id, ExecutionStatus.AWAITING_AUTHORIZATION, 100
        )
        now = datetime.now(UTC)
        count = 0
        for ex in rows:
            if ex.escalation_request and ex.escalation_request.expires_at < now:
                ex.expire_escalation()
                await self._executions.save(ex, tenant_id)
                count += 1
        self.expired += count
        return count


class OutboxRecoveryWorker:
    def __init__(self, records: Any, connector_port: Any) -> None:
        self._records = records
        self._connectors = connector_port
        self.recovered = 0

    async def tick(self) -> int:
        stale = await self._records.find_pending_recovery(5)
        count = 0
        for record in stale:
            verified = await self._connectors.verify_outcome(
                str(record.tenant_id),
                record.connector_type,
                str(record.execution_id),
                record.step_number,
            )
            if verified is None:
                continue
            if verified.success:
                record.complete(
                    __import__(
                        "automated_action.domain.value_objects.enums", fromlist=["ActionOutcome"]
                    ).ActionOutcome.SUCCESS,
                    verified.external_reference,
                    verified.duration_ms,
                )
                await self._records.update_status(
                    record.record_id,
                    record.tenant_id,
                    ActionRecordStatus.COMPLETED,
                    record.outcome,
                    verified.external_reference,
                    None,
                    datetime.now(UTC),
                    verified.duration_ms,
                )
            else:
                from automated_action.domain.value_objects.enums import (
                    ActionOutcome,
                    ConnectorFailureMode,
                )

                mode = ConnectorFailureMode(verified.failure_mode or "SERVER_ERROR")
                record.fail(mode, verified.duration_ms)
                await self._records.update_status(
                    record.record_id,
                    record.tenant_id,
                    ActionRecordStatus.FAILED,
                    ActionOutcome.FAILURE,
                    None,
                    mode,
                    datetime.now(UTC),
                    verified.duration_ms,
                )
            count += 1
        self.recovered += count
        return count


class RetryWorker:
    def __init__(self) -> None:
        self.dead_letters: list[dict[str, object]] = []
        self.ticks = 0

    def tick(self) -> None:
        self.ticks += 1


class RecoveryWorker:
    def __init__(self) -> None:
        self.ticks = 0

    def tick(self) -> None:
        self.ticks += 1


class MetricsWorker:
    def __init__(self, metrics: Any) -> None:
        self._metrics = metrics
        self.ticks = 0

    def tick(self) -> dict[str, float]:
        self.ticks += 1
        return dict(self._metrics.counters)


class ExecutionScheduler:
    def __init__(self, execution_worker: PlaybookExecutionWorker, executions: Any) -> None:
        self.execution_worker = execution_worker
        self._executions = executions

    async def tick(self, tenant_id: TenantId) -> int:

        pending = await self._executions.find_by_status(
            tenant_id, ExecutionStatus.PENDING, 50
        )
        for ex in pending:
            await self.execution_worker.process(tenant_id, ex.execution_id.value)
        return len(pending)


class AutomationScheduler:
    def __init__(
        self,
        execution_scheduler: ExecutionScheduler,
        escalation_worker: EscalationTimeoutWorker,
        outbox_worker: OutboxRecoveryWorker,
        retry_worker: RetryWorker,
        recovery_worker: RecoveryWorker,
        metrics_worker: MetricsWorker,
    ) -> None:
        self.execution_scheduler = execution_scheduler
        self.escalation_worker = escalation_worker
        self.outbox_worker = outbox_worker
        self.retry_worker = retry_worker
        self.recovery_worker = recovery_worker
        self.metrics_worker = metrics_worker

    async def tick_all(self, tenant_id: TenantId) -> dict[str, int]:
        pending = await self.execution_scheduler.tick(tenant_id)
        expired = await self.escalation_worker.tick(tenant_id)
        recovered = await self.outbox_worker.tick()
        self.retry_worker.tick()
        self.recovery_worker.tick()
        self.metrics_worker.tick()
        return {
            "pending_processed": pending,
            "escalations_expired": expired,
            "outbox_recovered": recovered,
        }
