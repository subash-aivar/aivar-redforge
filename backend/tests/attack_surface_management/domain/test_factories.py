from __future__ import annotations

from datetime import UTC, datetime

from attack_surface_management.domain.factories.asset_factory import AssetFactory
from attack_surface_management.domain.factories.network_range_factory import (
    NetworkRangeFactory,
)
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.enums import AssetType, DiscoverySource
from attack_surface_management.domain.value_objects.identifiers import AssetId, TenantId
from attack_surface_management.domain.value_objects.ip_address import IPAddress

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def test_asset_factory_generates_id_when_not_supplied(tenant_id: TenantId) -> None:
    asset = AssetFactory.discover(
        tenant_id=tenant_id,
        asset_type=AssetType.EXTERNAL,
        now=NOW,
        ip_address=IPAddress("8.8.8.8"),
        discovery_source=DiscoverySource.ACTIVE_SCAN,
    )
    assert asset.asset_id is not None
    assert asset.discovery_source == DiscoverySource.ACTIVE_SCAN


def test_asset_factory_accepts_explicit_id(tenant_id: TenantId) -> None:
    explicit_id = AssetId.generate()
    asset = AssetFactory.discover(
        tenant_id=tenant_id,
        asset_type=AssetType.EXTERNAL,
        now=NOW,
        domain_name=DomainName("example.com"),
        asset_id=explicit_id,
    )
    assert asset.asset_id == explicit_id


def test_network_range_factory_generates_id_when_not_supplied(tenant_id: TenantId) -> None:
    net_range = NetworkRangeFactory.discover(
        tenant_id=tenant_id, cidr=CidrBlock("192.168.0.0/24"), now=NOW
    )
    assert net_range.range_id is not None
