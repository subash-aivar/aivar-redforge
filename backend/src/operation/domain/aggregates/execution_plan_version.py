"""ExecutionPlanVersion aggregate — immutable signed plan snapshots."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from operation.domain.events.plan_version_events import (
    ExecutionPlanVersionArchived,
    ExecutionPlanVersionCreated,
    ExecutionPlanVersionExecuted,
    ExecutionPlanVersionExecuting,
    ExecutionPlanVersionSigned,
    ExecutionPlanVersionSuperseded,
)
from operation.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    PlanImmutabilityViolation,
    TenantMismatch,
)
from operation.domain.value_objects.enums import ExecutionPlanVersionState
from operation.domain.value_objects.identifiers import ExecutionPlanVersionId
from operation.domain.value_objects.plan_vos import PlanHash, SignedBy

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from operation.domain.events.base import BaseDomainEvent
    from operation.domain.value_objects.identifiers import OperationId, TenantId
    from operation.domain.value_objects.plan_vos import PlanSnapshot

_ALLOWED: dict[ExecutionPlanVersionState, frozenset[ExecutionPlanVersionState]] = {
    ExecutionPlanVersionState.DRAFT: frozenset(
        {
            ExecutionPlanVersionState.SIGNED,
            ExecutionPlanVersionState.SUPERSEDED,
            ExecutionPlanVersionState.ARCHIVED,
        }
    ),
    ExecutionPlanVersionState.SIGNED: frozenset(
        {
            ExecutionPlanVersionState.EXECUTING,
            ExecutionPlanVersionState.SUPERSEDED,
            ExecutionPlanVersionState.ARCHIVED,
        }
    ),
    ExecutionPlanVersionState.EXECUTING: frozenset(
        {
            ExecutionPlanVersionState.EXECUTED,
            ExecutionPlanVersionState.SUPERSEDED,
            ExecutionPlanVersionState.ARCHIVED,
        }
    ),
    ExecutionPlanVersionState.EXECUTED: frozenset(
        {
            ExecutionPlanVersionState.ARCHIVED,
        }
    ),
    ExecutionPlanVersionState.SUPERSEDED: frozenset(
        {
            ExecutionPlanVersionState.ARCHIVED,
        }
    ),
    ExecutionPlanVersionState.ARCHIVED: frozenset(),
}


class ExecutionPlanVersion:
    """Immutable snapshot of an ExecutionPlan once signed."""

    __slots__ = (
        "_pending_events",
        "_version",
        "created_at",
        "operation_id",
        "plan_hash",
        "plan_version_id",
        "signed_by",
        "snapshot",
        "state",
        "tenant_id",
        "updated_at",
        "version_number",
    )

    def __init__(
        self,
        plan_version_id: ExecutionPlanVersionId,
        tenant_id: TenantId,
        operation_id: OperationId,
        version_number: int,
        snapshot: PlanSnapshot,
        plan_hash: PlanHash | None,
        signed_by: SignedBy | None,
        state: ExecutionPlanVersionState,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.plan_version_id = plan_version_id
        self.tenant_id = tenant_id
        self.operation_id = operation_id
        self.version_number = version_number
        self.snapshot = snapshot
        self.plan_hash = plan_hash
        self.signed_by = signed_by
        self.state = state
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_mutable(self) -> None:
        if self.state != ExecutionPlanVersionState.DRAFT:
            raise PlanImmutabilityViolation(self.plan_version_id)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: ExecutionPlanVersionState) -> None:
        allowed = _ALLOWED.get(self.state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.state.value,
                to_state.value,
                str(self.plan_version_id),
            )
        self.state = to_state

    @classmethod
    def create_draft(
        cls,
        *,
        tenant_id: TenantId,
        operation_id: OperationId,
        version_number: int,
        snapshot: PlanSnapshot,
        now: datetime,
        plan_version_id: ExecutionPlanVersionId | None = None,
    ) -> ExecutionPlanVersion:
        if version_number < 1:
            raise InvalidArgument("version_number", "must be >= 1")
        pid = plan_version_id or ExecutionPlanVersionId.generate()
        aggregate = cls(
            plan_version_id=pid,
            tenant_id=tenant_id,
            operation_id=operation_id,
            version_number=version_number,
            snapshot=snapshot,
            plan_hash=None,
            signed_by=None,
            state=ExecutionPlanVersionState.DRAFT,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            ExecutionPlanVersionCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(pid),
                aggregate_type="ExecutionPlanVersion",
                operation_id=str(operation_id),
                version_number=version_number,
            )
        )
        return aggregate

    def replace_snapshot(
        self,
        *,
        tenant_id: TenantId,
        snapshot: PlanSnapshot,
        now: datetime,
    ) -> None:
        """Allowed only while Draft — ADR-M29-005 immutability after Signed."""
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.snapshot = snapshot
        self.plan_hash = None
        self._mutate(now)

    def sign(
        self,
        *,
        tenant_id: TenantId,
        operator_id: UUID,
        signature: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ExecutionPlanVersionState.DRAFT:
            raise InvalidStateTransition(
                self.state.value,
                ExecutionPlanVersionState.SIGNED.value,
                str(self.plan_version_id),
            )
        plan_hash = PlanHash.from_snapshot(self.snapshot)
        signed_by = SignedBy(
            operator_id=operator_id,
            signed_at=now,
            signature=signature,
        )
        self.plan_hash = plan_hash
        self.signed_by = signed_by
        self._transition(ExecutionPlanVersionState.SIGNED)
        self._mutate(now)
        self._emit(
            ExecutionPlanVersionSigned(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.plan_version_id),
                aggregate_type="ExecutionPlanVersion",
                operation_id=str(self.operation_id),
                version_number=self.version_number,
                plan_hash=plan_hash.value,
                signed_by=str(operator_id),
            )
        )

    def supersede(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(ExecutionPlanVersionState.SUPERSEDED)
        self._mutate(now)
        self._emit(
            ExecutionPlanVersionSuperseded(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.plan_version_id),
                aggregate_type="ExecutionPlanVersion",
                operation_id=str(self.operation_id),
                version_number=self.version_number,
            )
        )

    def mark_executing(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(ExecutionPlanVersionState.EXECUTING)
        self._mutate(now)
        self._emit(
            ExecutionPlanVersionExecuting(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.plan_version_id),
                aggregate_type="ExecutionPlanVersion",
                operation_id=str(self.operation_id),
                version_number=self.version_number,
            )
        )

    def mark_executed(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(ExecutionPlanVersionState.EXECUTED)
        self._mutate(now)
        self._emit(
            ExecutionPlanVersionExecuted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.plan_version_id),
                aggregate_type="ExecutionPlanVersion",
                operation_id=str(self.operation_id),
                version_number=self.version_number,
            )
        )

    def archive(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(ExecutionPlanVersionState.ARCHIVED)
        self._mutate(now)
        self._emit(
            ExecutionPlanVersionArchived(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.plan_version_id),
                aggregate_type="ExecutionPlanVersion",
                operation_id=str(self.operation_id),
                version_number=self.version_number,
            )
        )
