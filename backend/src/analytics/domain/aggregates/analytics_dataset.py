"""AnalyticsDataSet aggregate — projection registration and checkpoints."""

from __future__ import annotations

from typing import TYPE_CHECKING

from analytics.domain.events.analytics_events import (
    AnalyticsDataSetPopulated,
    AnalyticsDataSetRebuildCompleted,
    AnalyticsDataSetRebuildStarted,
    AnalyticsDataSetRegistered,
)
from analytics.domain.exceptions.domain_exceptions import InvalidDataSetTransition, TenantMismatch
from analytics.domain.value_objects.enums import DataSetStatus, SecurityDomain

if TYPE_CHECKING:
    from datetime import datetime

    from analytics.domain.events.base import BaseDomainEvent
    from analytics.domain.value_objects.identifiers import AnalyticsDataSetId, TenantId


class AnalyticsDataSet:
    __slots__ = (
        "_pending_events",
        "created_at",
        "dataset_id",
        "domain",
        "projection_checkpoint",
        "records_ingested",
        "schema_version",
        "status",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        dataset_id: AnalyticsDataSetId,
        tenant_id: TenantId,
        domain: SecurityDomain,
        schema_version: str,
        status: DataSetStatus,
        created_at: datetime,
        updated_at: datetime,
        projection_checkpoint: str | None = None,
        records_ingested: int = 0,
    ) -> None:
        self.dataset_id = dataset_id
        self.tenant_id = tenant_id
        self.domain = domain
        self.schema_version = schema_version
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at
        self.projection_checkpoint = projection_checkpoint
        self.records_ingested = records_ingested
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def register(
        cls,
        dataset_id: AnalyticsDataSetId,
        tenant_id: TenantId,
        domain: SecurityDomain,
        schema_version: str,
        at: datetime,
    ) -> AnalyticsDataSet:
        ds = cls(
            dataset_id,
            tenant_id,
            domain,
            schema_version,
            DataSetStatus.ACTIVE,
            at,
            at,
        )
        ds._emit(
            AnalyticsDataSetRegistered(
                tenant_id=str(tenant_id),
                aggregate_id=str(dataset_id),
                domain=domain.value,
                schema_version=schema_version,
            )
        )
        return ds

    def advance_checkpoint(
        self, tenant_id: TenantId, event_id: str, at: datetime, *, ingested: int = 1
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        self.projection_checkpoint = event_id
        self.records_ingested += ingested
        self.updated_at = at
        self._emit(
            AnalyticsDataSetPopulated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.dataset_id),
                records_ingested=self.records_ingested,
                checkpoint=event_id,
            )
        )

    def begin_rebuild(self, tenant_id: TenantId, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if self.status == DataSetStatus.REBUILDING:
            raise InvalidDataSetTransition("already rebuilding")
        self.status = DataSetStatus.REBUILDING
        self.updated_at = at
        self._emit(
            AnalyticsDataSetRebuildStarted(
                tenant_id=str(tenant_id), aggregate_id=str(self.dataset_id)
            )
        )

    def complete_rebuild(
        self, tenant_id: TenantId, checkpoint: str, at: datetime, records: int
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        self.status = DataSetStatus.ACTIVE
        self.projection_checkpoint = checkpoint
        self.records_ingested = records
        self.updated_at = at
        self._emit(
            AnalyticsDataSetRebuildCompleted(
                tenant_id=str(tenant_id), aggregate_id=str(self.dataset_id)
            )
        )
