"""TelemetrySource aggregate root — authorized telemetry provider metadata."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from detection.domain.events.telemetry_events import (
    TelemetrySourceDeactivated,
    TelemetrySourceHealthChanged,
    TelemetrySourceRegistered,
    TelemetrySourceSchemaUpdated,
)
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    TenantMismatch,
)
from detection.domain.value_objects.enums import (
    SourceHealthStatus,
    SourceLifecycleState,
)
from detection.domain.value_objects.identifiers import TelemetrySourceId
from detection.domain.value_objects.telemetry import SourceHealth

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import SourceTrustLevel, SourceType
    from detection.domain.value_objects.identifiers import TenantId
    from detection.domain.value_objects.telemetry import (
        ConnectionConfig,
        DataLatencyProfile,
        RetentionWindow,
        SourceSchema,
    )

_ALLOWED_TRANSITIONS: dict[SourceLifecycleState, frozenset[SourceLifecycleState]] = {
    SourceLifecycleState.ACTIVE: frozenset({SourceLifecycleState.DEACTIVATED}),
    SourceLifecycleState.DEACTIVATED: frozenset({SourceLifecycleState.ACTIVE}),
}


class TelemetrySource:
    """
    Configuration aggregate for a registered telemetry provider.

    Does not store telemetry. Owns schema contract, connection routing,
    health, trust, latency, and retention metadata.
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "connection",
        "created_at",
        "description",
        "health",
        "latency_profile",
        "lifecycle_state",
        "name",
        "retention",
        "schema",
        "source_id",
        "source_type",
        "tenant_id",
        "trust_level",
        "updated_at",
    )

    def __init__(
        self,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
        name: str,
        source_type: SourceType,
        trust_level: SourceTrustLevel,
        schema: SourceSchema,
        connection: ConnectionConfig,
        health: SourceHealth,
        latency_profile: DataLatencyProfile,
        retention: RetentionWindow,
        lifecycle_state: SourceLifecycleState,
        description: str | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.source_id = source_id
        self.tenant_id = tenant_id
        self.name = name
        self.source_type = source_type
        self.trust_level = trust_level
        self.schema = schema
        self.connection = connection
        self.health = health
        self.latency_profile = latency_profile
        self.retention = retention
        self.lifecycle_state = lifecycle_state
        self.description = description
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def is_active(self) -> bool:
        return self.lifecycle_state == SourceLifecycleState.ACTIVE

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _transition(self, to_state: SourceLifecycleState) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.lifecycle_state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.lifecycle_state.value,
                to_state.value,
            )
        self.lifecycle_state = to_state

    @classmethod
    def register(
        cls,
        *,
        tenant_id: TenantId,
        name: str,
        source_type: SourceType,
        trust_level: SourceTrustLevel,
        schema: SourceSchema,
        connection: ConnectionConfig,
        latency_profile: DataLatencyProfile,
        retention: RetentionWindow,
        description: str | None = None,
        now: datetime,
        source_id: TelemetrySourceId | None = None,
    ) -> TelemetrySource:
        if not name.strip():
            raise InvalidArgument("name", "required")
        sid = source_id or TelemetrySourceId.generate()
        aggregate = cls(
            source_id=sid,
            tenant_id=tenant_id,
            name=name.strip()[:256],
            source_type=source_type,
            trust_level=trust_level,
            schema=schema,
            connection=connection,
            health=SourceHealth.unknown(),
            latency_profile=latency_profile,
            retention=retention,
            lifecycle_state=SourceLifecycleState.ACTIVE,
            description=description.strip()[:1024] if description else None,
            created_at=now,
            updated_at=now,
            version=0,
        )
        aggregate._emit(
            TelemetrySourceRegistered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(sid),
                aggregate_type="TelemetrySource",
                name=aggregate.name,
                source_type=source_type.value,
                schema_version=schema.schema_version,
                trust_level=trust_level.value,
            )
        )
        return aggregate

    def deactivate(
        self,
        *,
        tenant_id: TenantId,
        reason: str,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "required")
        self._transition(SourceLifecycleState.DEACTIVATED)
        self._mutate(now)
        self._emit(
            TelemetrySourceDeactivated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.source_id),
                aggregate_type="TelemetrySource",
                reason=reason.strip()[:1024],
            )
        )

    def reactivate(
        self,
        *,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._transition(SourceLifecycleState.ACTIVE)
        self._mutate(now)

    def update_health(
        self,
        *,
        tenant_id: TenantId,
        status: SourceHealthStatus,
        now: datetime,
        detail: str | None = None,
        success: bool | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        previous = self.health.status
        failures = self.health.consecutive_failures
        last_success = self.health.last_success_at
        last_failure = self.health.last_failure_at
        last_error = self.health.last_error

        if success is True:
            failures = 0
            last_success = now
            last_error = None
        elif success is False:
            failures += 1
            last_failure = now
            last_error = detail

        self.health = SourceHealth(
            status=status,
            last_checked_at=now,
            last_success_at=last_success,
            last_failure_at=last_failure,
            last_error=last_error,
            consecutive_failures=failures,
        )
        self._mutate(now)
        if previous != status:
            self._emit(
                TelemetrySourceHealthChanged(
                    event_id=str(uuid7()),
                    occurred_at=now,
                    tenant_id=self.tenant_id,
                    aggregate_id=str(self.source_id),
                    aggregate_type="TelemetrySource",
                    previous_status=previous.value,
                    new_status=status.value,
                    detail=detail,
                )
            )

    def update_schema(
        self,
        *,
        tenant_id: TenantId,
        schema: SourceSchema,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        previous = self.schema.schema_version
        if schema.schema_version == previous and schema.field_paths() == self.schema.field_paths():
            return
        self.schema = schema
        self._mutate(now)
        self._emit(
            TelemetrySourceSchemaUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.source_id),
                aggregate_type="TelemetrySource",
                previous_schema_version=previous,
                new_schema_version=schema.schema_version,
            )
        )

    def update_connection(
        self,
        *,
        tenant_id: TenantId,
        connection: ConnectionConfig,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self.connection = connection
        self._mutate(now)

    def update_metadata(
        self,
        *,
        tenant_id: TenantId,
        now: datetime,
        description: str | None = None,
        trust_level: SourceTrustLevel | None = None,
        latency_profile: DataLatencyProfile | None = None,
        retention: RetentionWindow | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if description is not None:
            self.description = description.strip()[:1024] if description else None
        if trust_level is not None:
            self.trust_level = trust_level
        if latency_profile is not None:
            self.latency_profile = latency_profile
        if retention is not None:
            self.retention = retention
        self._mutate(now)
