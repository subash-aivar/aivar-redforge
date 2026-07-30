from __future__ import annotations

import uuid

import pytest

from attack_surface_management.application.commands.asset_commands import RegisterAssetCommand
from attack_surface_management.application.commands.network_range_commands import (
    FormNetworkRangeCommand,
)
from attack_surface_management.application.exceptions import InvalidPaginationError
from attack_surface_management.application.queries.asset_queries import (
    GetAssetQuery,
    ListAssetsQuery,
)
from attack_surface_management.application.queries.network_range_queries import (
    GetNetworkRangeQuery,
    ListNetworkRangesQuery,
)
from attack_surface_management.application.services.asset_application_service import (
    AssetApplicationService,
)
from attack_surface_management.application.services.attack_surface_query_service import (
    AttackSurfaceQueryService,
)
from attack_surface_management.application.services.network_range_application_service import (
    NetworkRangeApplicationService,
)
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.enums import AssetType
from attack_surface_management.domain.value_objects.identifiers import AssetId, NetworkRangeId


@pytest.fixture
def asset_service(asset_repository, unit_of_work) -> AssetApplicationService:
    return AssetApplicationService(asset_repository, unit_of_work)


@pytest.fixture
def range_service(network_range_repository, unit_of_work) -> NetworkRangeApplicationService:
    return NetworkRangeApplicationService(network_range_repository, unit_of_work)


@pytest.fixture
def query_service(asset_repository, network_range_repository) -> AttackSurfaceQueryService:
    return AttackSurfaceQueryService(asset_repository, network_range_repository)


class TestGetAsset:
    async def test_returns_dto_for_existing_asset(self, asset_service, query_service, tenant_id):
        registered = await asset_service.register_asset(
            RegisterAssetCommand(
                tenant_id=tenant_id,
                asset_type=AssetType.INTERNAL,
                domain_name=DomainName("internal.example.com"),
            )
        )
        asset_id = AssetId(uuid.UUID(registered.asset_id))
        dto = await query_service.get_asset(GetAssetQuery(tenant_id=tenant_id, asset_id=asset_id))
        assert dto is not None
        assert dto.asset_id == registered.asset_id

    async def test_returns_none_for_missing_asset(self, query_service, tenant_id):
        dto = await query_service.get_asset(
            GetAssetQuery(tenant_id=tenant_id, asset_id=AssetId.generate())
        )
        assert dto is None

    async def test_cross_tenant_returns_none(
        self, asset_service, query_service, tenant_id, other_tenant_id
    ):
        registered = await asset_service.register_asset(
            RegisterAssetCommand(
                tenant_id=tenant_id,
                asset_type=AssetType.INTERNAL,
                domain_name=DomainName("internal.example.com"),
            )
        )
        asset_id = AssetId(uuid.UUID(registered.asset_id))
        dto = await query_service.get_asset(
            GetAssetQuery(tenant_id=other_tenant_id, asset_id=asset_id)
        )
        assert dto is None


class TestListAssets:
    async def test_lists_only_own_tenant_assets(
        self, asset_service, query_service, tenant_id, other_tenant_id
    ):
        await asset_service.register_asset(
            RegisterAssetCommand(
                tenant_id=tenant_id,
                asset_type=AssetType.INTERNAL,
                domain_name=DomainName("a.example.com"),
            )
        )
        await asset_service.register_asset(
            RegisterAssetCommand(
                tenant_id=other_tenant_id,
                asset_type=AssetType.INTERNAL,
                domain_name=DomainName("b.example.com"),
            )
        )
        results = await query_service.list_assets(ListAssetsQuery(tenant_id=tenant_id))
        assert len(results) == 1
        assert results[0].tenant_id == str(tenant_id)

    async def test_invalid_pagination_raises(self, query_service, tenant_id):
        with pytest.raises(InvalidPaginationError):
            await query_service.list_assets(ListAssetsQuery(tenant_id=tenant_id, limit=0))
        with pytest.raises(InvalidPaginationError):
            await query_service.list_assets(ListAssetsQuery(tenant_id=tenant_id, offset=-1))


class TestNetworkRangeQueries:
    async def test_get_and_list_network_ranges(self, range_service, query_service, tenant_id):
        formed = await range_service.form_network_range(
            FormNetworkRangeCommand(tenant_id=tenant_id, cidr=CidrBlock("192.168.1.0/24"))
        )
        range_id = NetworkRangeId(uuid.UUID(formed.range_id))
        dto = await query_service.get_network_range(
            GetNetworkRangeQuery(tenant_id=tenant_id, range_id=range_id)
        )
        assert dto is not None
        assert dto.cidr == "192.168.1.0/24"

        results = await query_service.list_network_ranges(
            ListNetworkRangesQuery(tenant_id=tenant_id)
        )
        assert len(results) == 1

    async def test_get_network_range_returns_none_when_missing(self, query_service, tenant_id):
        dto = await query_service.get_network_range(
            GetNetworkRangeQuery(tenant_id=tenant_id, range_id=NetworkRangeId.generate())
        )
        assert dto is None
