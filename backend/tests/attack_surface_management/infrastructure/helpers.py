"""Shared aggregate builders for attack_surface_management
infrastructure tests."""

from __future__ import annotations

from datetime import UTC, datetime

from ulid import ULID

from attack_surface_management.domain.factories.asset_factory import AssetFactory
from attack_surface_management.domain.factories.network_range_factory import NetworkRangeFactory
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.enums import AssetType, DiscoverySource
from attack_surface_management.domain.value_objects.identifiers import TenantId
from attack_surface_management.domain.value_objects.ip_address import IPAddress


def make_tenant_id() -> TenantId:
    return TenantId(ULID())


def make_asset(
    tenant_id: TenantId,
    *,
    domain: str = "example.com",
    asset_type: AssetType = AssetType.EXTERNAL,
    discovery_source: DiscoverySource = DiscoverySource.PASSIVE_DNS,
    now: datetime | None = None,
):
    now = now or datetime.now(UTC)
    return AssetFactory.discover(
        tenant_id=tenant_id,
        asset_type=asset_type,
        now=now,
        domain_name=DomainName(domain),
        discovery_source=discovery_source,
    )


def make_asset_with_ip(
    tenant_id: TenantId,
    *,
    ip: str = "203.0.113.10",
    asset_type: AssetType = AssetType.INTERNET_FACING,
    now: datetime | None = None,
):
    now = now or datetime.now(UTC)
    return AssetFactory.discover(
        tenant_id=tenant_id,
        asset_type=asset_type,
        now=now,
        ip_address=IPAddress(ip),
        discovery_source=DiscoverySource.ACTIVE_SCAN,
    )


def make_network_range(
    tenant_id: TenantId,
    *,
    cidr: str = "10.0.0.0/24",
    discovery_source: DiscoverySource = DiscoverySource.WHOIS,
    now: datetime | None = None,
):
    now = now or datetime.now(UTC)
    return NetworkRangeFactory.discover(
        tenant_id=tenant_id,
        cidr=CidrBlock(cidr),
        now=now,
        discovery_source=discovery_source,
    )
