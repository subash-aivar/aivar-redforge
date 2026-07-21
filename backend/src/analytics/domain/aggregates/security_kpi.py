"""SecurityKPI aggregate — definition, schedule, latest value."""

from __future__ import annotations

from typing import TYPE_CHECKING

from analytics.domain.events.analytics_events import KPIComputationFailed, KPIComputed
from analytics.domain.exceptions.domain_exceptions import TenantMismatch
from analytics.domain.value_objects.enums import KPIStatus, KPIType

if TYPE_CHECKING:
    from datetime import datetime

    from analytics.domain.events.base import BaseDomainEvent
    from analytics.domain.value_objects.identifiers import SecurityKPIId, TenantId


class SecurityKPI:
    __slots__ = (
        "_pending_events",
        "computation_schedule_cron",
        "created_at",
        "definition_version",
        "kpi_id",
        "kpi_type",
        "last_computed_at",
        "latest_unit",
        "latest_value",
        "status",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        kpi_id: SecurityKPIId,
        tenant_id: TenantId,
        kpi_type: KPIType,
        computation_schedule_cron: str,
        status: KPIStatus,
        definition_version: int,
        created_at: datetime,
        updated_at: datetime,
        latest_value: float | None = None,
        latest_unit: str = "",
        last_computed_at: datetime | None = None,
    ) -> None:
        self.kpi_id = kpi_id
        self.tenant_id = tenant_id
        self.kpi_type = kpi_type
        self.computation_schedule_cron = computation_schedule_cron
        self.status = status
        self.definition_version = definition_version
        self.created_at = created_at
        self.updated_at = updated_at
        self.latest_value = latest_value
        self.latest_unit = latest_unit
        self.last_computed_at = last_computed_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def define(
        cls,
        kpi_id: SecurityKPIId,
        tenant_id: TenantId,
        kpi_type: KPIType,
        schedule_cron: str,
        at: datetime,
    ) -> SecurityKPI:
        status = KPIStatus.REQUIRES_M34_DATA if kpi_type == KPIType.MTTR else KPIStatus.ACTIVE
        return cls(
            kpi_id,
            tenant_id,
            kpi_type,
            schedule_cron,
            status,
            1,
            at,
            at,
        )

    def record_computation(
        self,
        tenant_id: TenantId,
        *,
        value: float | None,
        unit: str,
        status: KPIStatus,
        at: datetime,
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        self.latest_value = value
        self.latest_unit = unit
        self.status = status
        self.last_computed_at = at
        self.updated_at = at
        if status == KPIStatus.ERROR:
            self._emit(
                KPIComputationFailed(
                    tenant_id=str(tenant_id),
                    aggregate_id=str(self.kpi_id),
                    kpi_type=self.kpi_type.value,
                    error_reason="computation error",
                )
            )
        else:
            self._emit(
                KPIComputed(
                    tenant_id=str(tenant_id),
                    aggregate_id=str(self.kpi_id),
                    kpi_type=self.kpi_type.value,
                    value=value,
                    unit=unit,
                    definition_version=self.definition_version,
                )
            )
