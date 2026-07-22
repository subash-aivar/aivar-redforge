"""AutomatedActionRecord — outbox evidence (ADR-M35-002)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from automated_action.domain.value_objects.enums import (
    ActionOutcome,
    ActionRecordStatus,
    ConnectorFailureMode,
)
from automated_action.domain.value_objects.identifiers import (
    AutomatedActionRecordId,
    AutomationExecutionId,
    TenantId,
)


@dataclass
class AutomatedActionRecord:
    record_id: AutomatedActionRecordId
    tenant_id: TenantId
    execution_id: AutomationExecutionId
    step_number: int
    action_type: str
    connector_type: str
    target_resource: str
    parameters_hash: str
    status: ActionRecordStatus
    outcome: ActionOutcome | None
    external_reference: str | None
    failure_mode: ConnectorFailureMode | None
    attempted_at: datetime
    completed_at: datetime | None
    duration_ms: int | None
    rollback_available: bool
    rollback_parameters_ref: str | None

    @staticmethod
    def hash_parameters(parameters: dict[str, object]) -> str:
        payload = json.dumps(parameters, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return sha256(payload).hexdigest()

    @classmethod
    def create_pending(
        cls,
        tenant_id: TenantId,
        execution_id: AutomationExecutionId,
        step_number: int,
        action_type: str,
        connector_type: str,
        target_resource: str,
        parameters: dict[str, object],
    ) -> AutomatedActionRecord:
        return cls(
            AutomatedActionRecordId.generate(),
            tenant_id,
            execution_id,
            step_number,
            action_type,
            connector_type,
            target_resource,
            cls.hash_parameters(parameters),
            ActionRecordStatus.PENDING,
            None,
            None,
            None,
            datetime.now(UTC),
            None,
            None,
            False,
            None,
        )

    def complete(
        self,
        outcome: ActionOutcome,
        external_reference: str | None,
        duration_ms: int,
        *,
        rollback_available: bool = False,
        rollback_parameters_ref: str | None = None,
    ) -> None:
        self.status = ActionRecordStatus.COMPLETED
        self.outcome = outcome
        self.external_reference = external_reference
        self.completed_at = datetime.now(UTC)
        self.duration_ms = duration_ms
        self.rollback_available = rollback_available
        self.rollback_parameters_ref = rollback_parameters_ref

    def fail(self, failure_mode: ConnectorFailureMode, duration_ms: int) -> None:
        self.status = ActionRecordStatus.FAILED
        self.outcome = ActionOutcome.FAILURE
        self.failure_mode = failure_mode
        self.completed_at = datetime.now(UTC)
        self.duration_ms = duration_ms
