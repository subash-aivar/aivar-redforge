"""ACL adapter wrapping exposure_reporting BusinessImpactMapping lookups."""

from __future__ import annotations

from typing import TYPE_CHECKING

from exposure.domain.ports.i_business_impact_query_port import IBusinessImpactQueryPort

if TYPE_CHECKING:
    from uuid import UUID

    from exposure.domain.value_objects.identifiers import TenantId
    from exposure_reporting.domain.repositories.i_business_impact_mapping_repository import (
        IBusinessImpactMappingRepository,
    )


class BusinessImpactQueryAdapter(IBusinessImpactQueryPort):
    def __init__(self, mapping_repo: IBusinessImpactMappingRepository) -> None:
        self._repo = mapping_repo

    async def get_criticality(self, tenant_id: TenantId, asset_ref_id: UUID) -> str | None:
        from exposure_reporting.domain.value_objects.identifiers import (
            TenantId as RepTenantId,
        )

        mapping = await self._repo.find_by_asset(RepTenantId(tenant_id.value), asset_ref_id)
        return mapping.criticality.value if mapping else None


class StubBusinessImpactQueryAdapter(IBusinessImpactQueryPort):
    def __init__(self) -> None:
        self._rows: dict[str, str] = {}

    def seed(self, asset_ref_id: UUID, criticality: str) -> None:
        self._rows[str(asset_ref_id)] = criticality

    async def get_criticality(self, tenant_id: TenantId, asset_ref_id: UUID) -> str | None:
        del tenant_id
        return self._rows.get(str(asset_ref_id))
