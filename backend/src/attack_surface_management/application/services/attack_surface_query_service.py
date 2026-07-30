"""AttackSurfaceQueryService — the M49B read-only application service
orchestrating `GetAssetQuery`/`ListAssetsQuery`/`GetNetworkRangeQuery`/
`ListNetworkRangesQuery`, mirroring `risk_engine.application.services.
risk_query_service.RiskQueryService`'s combined-reader shape exactly
(both aggregate roots of this bounded context are colocated in one
query service since neither needs an extra domain service the way
`RiskTimelineApplicationService` did). Never mutates state; returns
DTOs only."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.application.exceptions import (
    AssetTenantIsolationViolationError,
)
from attack_surface_management.application.services.asset_application_service import (
    asset_to_dto,
)
from attack_surface_management.application.services.command_validation import (
    validate_pagination,
)
from attack_surface_management.application.services.network_range_application_service import (
    network_range_to_dto,
)

if TYPE_CHECKING:
    from attack_surface_management.application.dtos.asset_dto import AssetDTO, NetworkRangeDTO
    from attack_surface_management.application.ports.i_asset_repository import IAssetRepository
    from attack_surface_management.application.ports.i_network_range_repository import (
        INetworkRangeRepository,
    )
    from attack_surface_management.application.queries.asset_queries import (
        GetAssetQuery,
        ListAssetsQuery,
    )
    from attack_surface_management.application.queries.network_range_queries import (
        GetNetworkRangeQuery,
        ListNetworkRangesQuery,
    )


class AttackSurfaceQueryService:
    def __init__(
        self,
        asset_repository: IAssetRepository,
        network_range_repository: INetworkRangeRepository,
    ) -> None:
        self._assets = asset_repository
        self._network_ranges = network_range_repository

    # -- assets ------------------------------------------------------------

    async def get_asset(self, query: GetAssetQuery) -> AssetDTO | None:
        asset = await self._assets.get(query.tenant_id, query.asset_id)
        if asset is None:
            return None
        if asset.tenant_id != query.tenant_id:
            raise AssetTenantIsolationViolationError(query.tenant_id, asset.tenant_id)
        return asset_to_dto(asset)

    async def list_assets(self, query: ListAssetsQuery) -> tuple[AssetDTO, ...]:
        validate_pagination(query.limit, query.offset)
        filters: dict[str, object] = {}
        if query.asset_type is not None:
            filters["asset_type"] = query.asset_type
        if query.classification is not None:
            filters["classification"] = query.classification
        if query.criticality is not None:
            filters["criticality"] = query.criticality
        if query.exposure_state is not None:
            filters["exposure_state"] = query.exposure_state
        if query.lifecycle_state is not None:
            filters["lifecycle_state"] = query.lifecycle_state
        assets = await self._assets.list(query.tenant_id, **filters)
        matching = tuple(a for a in assets if a.tenant_id == query.tenant_id)
        page = matching[query.offset : query.offset + query.limit]
        return tuple(asset_to_dto(a) for a in page)

    # -- network ranges ----------------------------------------------------

    async def get_network_range(self, query: GetNetworkRangeQuery) -> NetworkRangeDTO | None:
        network_range = await self._network_ranges.get(query.tenant_id, query.range_id)
        if network_range is None:
            return None
        if network_range.tenant_id != query.tenant_id:
            raise AssetTenantIsolationViolationError(query.tenant_id, network_range.tenant_id)
        return network_range_to_dto(network_range)

    async def list_network_ranges(
        self, query: ListNetworkRangesQuery
    ) -> tuple[NetworkRangeDTO, ...]:
        validate_pagination(query.limit, query.offset)
        filters: dict[str, object] = {}
        if query.lifecycle_state is not None:
            filters["lifecycle_state"] = query.lifecycle_state
        network_ranges = await self._network_ranges.list(query.tenant_id, **filters)
        matching = tuple(r for r in network_ranges if r.tenant_id == query.tenant_id)
        page = matching[query.offset : query.offset + query.limit]
        return tuple(network_range_to_dto(r) for r in page)
