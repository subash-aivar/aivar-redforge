"""ACL facts for discovery completeness dashboards (Hardening §2)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.value_objects.identifiers import TenantId


class IDiscoveryScanFactsPort(ABC):
    @abstractmethod
    async def latest_scan_summary(self, tenant_id: TenantId) -> dict[str, object] | None: ...

    @abstractmethod
    async def configured_sources(self, tenant_id: TenantId) -> list[str]: ...
