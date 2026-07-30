"""IAssetRepository — an async ABC port for tenant-scoped persistence
of `Asset` aggregates, matching the platform-wide, post-M48C-correction
convention (`ABC` with `@abstractmethod async def`) used by
`risk_engine.application.ports.i_risk_profile_repository.
EnterpriseRiskProfileRepository` and every other mature bounded
context. `get`/`list` are tenant-scoped: `get` returns `None` for an
`asset_id` that exists but under a different tenant, never leaking
cross-tenant existence."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from attack_surface_management.domain.aggregates.asset import Asset
    from attack_surface_management.domain.value_objects.identifiers import AssetId, TenantId


class IAssetRepository(ABC):
    @abstractmethod
    async def save(self, asset: Asset) -> None: ...

    @abstractmethod
    async def get(self, tenant_id: TenantId, asset_id: AssetId) -> Asset | None: ...

    @abstractmethod
    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[Asset]: ...
