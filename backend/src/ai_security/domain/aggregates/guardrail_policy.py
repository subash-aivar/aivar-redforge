"""GuardrailPolicy aggregate — a policy *metadata* placeholder only
(M47A).

Owns a policy's identity, name, description, and assignment metadata
only — deliberately no actual guardrail enforcement or evaluation
logic, mirroring how `vulnerability_engine`'s M46A `ScanPolicy` was
pure metadata with no scan logic. References an `AiTarget` by id
only, never by object reference."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_security.domain.events.guardrail_policy_events import GuardrailAssigned
from ai_security.domain.exceptions.domain_exceptions import EmptyDisplayNameError, TenantMismatch

if TYPE_CHECKING:
    from datetime import datetime

    from ai_security.domain.events.base import BaseDomainEvent
    from ai_security.domain.value_objects.identifiers import PolicyId, TargetId, TenantId


class GuardrailPolicy:
    __slots__ = (
        "_pending_events",
        "assigned_target_ids",
        "created_at",
        "description",
        "name",
        "policy_id",
        "tenant_id",
    )

    def __init__(
        self,
        policy_id: PolicyId,
        tenant_id: TenantId,
        name: str,
        description: str,
        created_at: datetime,
        assigned_target_ids: tuple[TargetId, ...] = (),
    ) -> None:
        if not name.strip():
            raise EmptyDisplayNameError()
        self.policy_id = policy_id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.created_at = created_at
        self.assigned_target_ids = assigned_target_ids
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def create(
        cls,
        policy_id: PolicyId,
        tenant_id: TenantId,
        name: str,
        description: str,
        now: datetime,
    ) -> GuardrailPolicy:
        return cls(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name=name,
            description=description,
            created_at=now,
        )

    def assign_to_target(self, tenant_id: TenantId, target_id: TargetId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.assigned_target_ids = (*self.assigned_target_ids, target_id)
        self._emit(
            GuardrailAssigned(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.policy_id),
                aggregate_type="GuardrailPolicy",
                occurred_at=now,
                target_id=str(target_id),
            )
        )
