"""ITelemetrySourceRepository — tenant-scoped persistence port."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from detection.domain.aggregates.telemetry_source import TelemetrySource
    from detection.domain.value_objects.enums import SourceType
    from detection.domain.value_objects.identifiers import TelemetrySourceId, TenantId


class ITelemetrySourceRepository(ABC):
    @abstractmethod
    async def save(self, source: TelemetrySource) -> None:
        """Persist TelemetrySource aggregate."""

    @abstractmethod
    async def find_by_id(
        self,
        source_id: TelemetrySourceId,
        tenant_id: TenantId,
    ) -> TelemetrySource | None:
        """Load by id within tenant."""

    @abstractmethod
    async def find_by_name(
        self,
        name: str,
        tenant_id: TenantId,
    ) -> TelemetrySource | None:
        """Load by unique name within tenant."""

    @abstractmethod
    async def find_active_by_tenant(
        self,
        tenant_id: TenantId,
    ) -> list[TelemetrySource]:
        """List Active sources for tenant."""

    @abstractmethod
    async def find_by_type(
        self,
        source_type: SourceType,
        tenant_id: TenantId,
    ) -> list[TelemetrySource]:
        """List sources of a given type for tenant."""

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: TenantId,
        *,
        limit: int = 100,
        offset: int = 0,
    ) -> list[TelemetrySource]:
        """Paginated list of all sources for tenant."""
