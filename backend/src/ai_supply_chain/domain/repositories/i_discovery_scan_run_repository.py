from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_supply_chain.domain.aggregates.ai_discovery_scan_run import AIDiscoveryScanRun
    from ai_supply_chain.domain.value_objects.identifiers import (
        AIDiscoveryScanRunId,
        TenantId,
    )


class IDiscoveryScanRunRepository(ABC):
    @abstractmethod
    async def save(self, run: AIDiscoveryScanRun) -> None: ...

    @abstractmethod
    async def find_by_id(
        self, run_id: AIDiscoveryScanRunId, tenant_id: TenantId
    ) -> AIDiscoveryScanRun | None: ...

    @abstractmethod
    async def find_recent(self, tenant_id: TenantId, limit: int) -> list[AIDiscoveryScanRun]: ...
