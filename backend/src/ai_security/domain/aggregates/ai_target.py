"""AiTarget aggregate — a registered AI system under security scope
(M47A).

Owns identity, name, and a coarse type categorization only — no
attack-surface modeling, no prompt/evaluation/guardrail logic."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_security.domain.events.ai_target_events import AiTargetRegistered
from ai_security.domain.exceptions.domain_exceptions import EmptyDisplayNameError, TenantMismatch

if TYPE_CHECKING:
    from datetime import datetime

    from ai_security.domain.events.base import BaseDomainEvent
    from ai_security.domain.value_objects.enums import TargetType
    from ai_security.domain.value_objects.identifiers import TargetId, TenantId


class AiTarget:
    __slots__ = (
        "_pending_events",
        "name",
        "registered_at",
        "target_id",
        "target_type",
        "tenant_id",
    )

    def __init__(
        self,
        target_id: TargetId,
        tenant_id: TenantId,
        name: str,
        target_type: TargetType,
        registered_at: datetime,
    ) -> None:
        if not name.strip():
            raise EmptyDisplayNameError()
        self.target_id = target_id
        self.tenant_id = tenant_id
        self.name = name
        self.target_type = target_type
        self.registered_at = registered_at
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
    def register(
        cls,
        target_id: TargetId,
        tenant_id: TenantId,
        name: str,
        target_type: TargetType,
        now: datetime,
    ) -> AiTarget:
        target = cls(
            target_id=target_id,
            tenant_id=tenant_id,
            name=name,
            target_type=target_type,
            registered_at=now,
        )
        target._emit(
            AiTargetRegistered(
                tenant_id=str(tenant_id),
                aggregate_id=str(target_id),
                aggregate_type="AiTarget",
                occurred_at=now,
                target_type=str(target_type),
            )
        )
        return target
