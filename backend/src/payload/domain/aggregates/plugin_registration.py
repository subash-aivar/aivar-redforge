"""PluginRegistration aggregate — execution plugin governance."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from payload.domain.events.payload_events import (
    PluginApproved,
    PluginRegistered,
    PluginRevoked,
)
from payload.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from payload.domain.value_objects.enums import PluginApprovalState
from payload.domain.value_objects.identifiers import PluginId

if TYPE_CHECKING:
    from datetime import datetime

    from payload.domain.events.base import BaseDomainEvent
    from payload.domain.value_objects.enums import PluginTrustLevel, PluginType
    from payload.domain.value_objects.identifiers import OperatorId, TenantId
    from payload.domain.value_objects.payload_vos import (
        PluginCapabilities,
        PluginHash,
        PluginVersion,
    )

_ALLOWED: dict[PluginApprovalState, frozenset[PluginApprovalState]] = {
    PluginApprovalState.SUBMITTED: frozenset(
        {PluginApprovalState.APPROVED, PluginApprovalState.REVOKED}
    ),
    PluginApprovalState.APPROVED: frozenset({PluginApprovalState.REVOKED}),
    PluginApprovalState.REVOKED: frozenset(),
}

_AGGREGATE = "PluginRegistration"


class PluginRegistration:
    """Registry entry for an execution plugin bridging payload → infrastructure."""

    __slots__ = (
        "_pending_events",
        "_version",
        "approval_state",
        "capabilities",
        "created_at",
        "name",
        "plugin_hash",
        "plugin_id",
        "plugin_type",
        "plugin_version",
        "tenant_id",
        "trust_level",
        "updated_at",
    )

    def __init__(
        self,
        plugin_id: PluginId,
        tenant_id: TenantId,
        name: str,
        plugin_type: PluginType,
        plugin_version: PluginVersion,
        plugin_hash: PluginHash,
        capabilities: PluginCapabilities,
        trust_level: PluginTrustLevel,
        approval_state: PluginApprovalState,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.plugin_id = plugin_id
        self.tenant_id = tenant_id
        self.name = name
        self.plugin_type = plugin_type
        self.plugin_version = plugin_version
        self.plugin_hash = plugin_hash
        self.capabilities = capabilities
        self.trust_level = trust_level
        self.approval_state = approval_state
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> PluginId:
        return self.plugin_id

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _transition(self, to_state: PluginApprovalState) -> None:
        allowed = _ALLOWED.get(self.approval_state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.approval_state.value,
                to_state.value,
                str(self.plugin_id),
            )
        self.approval_state = to_state

    @classmethod
    def register(
        cls,
        *,
        tenant_id: TenantId,
        name: str,
        plugin_type: PluginType,
        plugin_version: PluginVersion,
        plugin_hash: PluginHash,
        capabilities: PluginCapabilities,
        trust_level: PluginTrustLevel,
        now: datetime,
    ) -> PluginRegistration:
        if not name:
            raise InvalidArgument("plugin name must not be empty")
        plugin_id = PluginId.generate()
        plugin = cls(
            plugin_id=plugin_id,
            tenant_id=tenant_id,
            name=name,
            plugin_type=plugin_type,
            plugin_version=plugin_version,
            plugin_hash=plugin_hash,
            capabilities=capabilities,
            trust_level=trust_level,
            approval_state=PluginApprovalState.SUBMITTED,
            created_at=now,
            updated_at=now,
            version=0,
        )
        plugin._emit(
            PluginRegistered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(plugin_id),
                aggregate_type=_AGGREGATE,
                plugin_type=plugin_type.value,
                plugin_version=plugin_version.value,
            )
        )
        return plugin

    def approve(
        self,
        *,
        tenant_id: TenantId,
        approved_by: OperatorId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._transition(PluginApprovalState.APPROVED)
        self._mutate(now)
        self._emit(
            PluginApproved(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.plugin_id),
                aggregate_type=_AGGREGATE,
                approved_by=str(approved_by),
            )
        )

    def revoke(
        self,
        *,
        tenant_id: TenantId,
        reason: str,
        revoked_by: OperatorId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason:
            raise InvalidArgument("revocation reason must not be empty")
        self._transition(PluginApprovalState.REVOKED)
        self._mutate(now)
        self._emit(
            PluginRevoked(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.plugin_id),
                aggregate_type=_AGGREGATE,
                reason=reason,
                revoked_by=str(revoked_by),
            )
        )
