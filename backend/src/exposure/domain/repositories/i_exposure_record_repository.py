"""IExposureRecordRepository — all methods require tenant_id first."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime

    from exposure.domain.aggregates.exposure_record import ExposureRecord
    from exposure.domain.value_objects.enums import RiskAmplifierType, SignalDomain
    from exposure.domain.value_objects.exposure_vos import AssetRef, SignalSourceRef
    from exposure.domain.value_objects.identifiers import ExposureRecordId, TenantId


class Page:
    def __init__(self, items: list[ExposureRecord], total: int, page: int, page_size: int) -> None:
        self.items = items
        self.total = total
        self.page = page
        self.page_size = page_size


class IExposureRecordRepository(ABC):
    @abstractmethod
    async def find_by_id(
        self, tenant_id: TenantId, record_id: ExposureRecordId
    ) -> ExposureRecord | None: ...

    @abstractmethod
    async def find_by_signal(
        self,
        tenant_id: TenantId,
        signal_domain: SignalDomain,
        signal_source_ref: SignalSourceRef,
    ) -> ExposureRecord | None: ...

    @abstractmethod
    async def find_by_asset(
        self, tenant_id: TenantId, asset_ref: AssetRef
    ) -> list[ExposureRecord]: ...

    @abstractmethod
    async def find_active_by_tenant(
        self, tenant_id: TenantId, page: int, page_size: int
    ) -> Page: ...

    @abstractmethod
    async def find_with_amplifier(
        self,
        tenant_id: TenantId,
        amplifier_type: RiskAmplifierType,
        page: int,
        page_size: int,
    ) -> Page: ...

    @abstractmethod
    async def find_stale_scores(
        self, tenant_id: TenantId, stale_before: datetime
    ) -> list[ExposureRecord]: ...

    @abstractmethod
    async def find_by_technique(
        self, tenant_id: TenantId, technique_ref: str
    ) -> list[ExposureRecord]: ...

    @abstractmethod
    async def save(self, tenant_id: TenantId, record: ExposureRecord) -> None: ...

    @abstractmethod
    async def save_batch(self, tenant_id: TenantId, records: list[ExposureRecord]) -> None: ...
