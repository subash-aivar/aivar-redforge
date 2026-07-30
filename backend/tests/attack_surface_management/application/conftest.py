"""Shared fixtures for attack_surface_management's application-layer
tests (M49B).

Fake, in-memory-dict implementations of `IAssetRepository`,
`INetworkRangeRepository` (async `ABC` ports) and the `IUnitOfWork` ABC
live here — never in `src/`, mirroring `risk_engine`'s own
`tests/risk_engine/application/conftest.py` precedent exactly."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from collections.abc import Sequence

    from attack_surface_management.domain.aggregates.asset import Asset
    from attack_surface_management.domain.aggregates.network_range import NetworkRange
    from attack_surface_management.domain.value_objects.identifiers import (
        AssetId,
        NetworkRangeId,
    )


class FakeAssetRepository:
    """An in-memory-dict fake satisfying `IAssetRepository` structurally
    (duck-typed against the async ABC) — local to tests only."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], Asset] = {}

    async def save(self, asset: Asset) -> None:
        self._by_key[(str(asset.tenant_id), str(asset.asset_id))] = asset

    async def get(self, tenant_id: TenantId, asset_id: AssetId) -> Asset | None:
        asset = self._by_key.get((str(tenant_id), str(asset_id)))
        if asset is None or asset.tenant_id != tenant_id:
            return None
        return asset

    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[Asset]:
        results = [a for (tid, _), a in self._by_key.items() if tid == str(tenant_id)]
        for field_name, value in filters.items():
            results = [a for a in results if getattr(a, field_name) == value]
        return tuple(results)


class FakeNetworkRangeRepository:
    def __init__(self) -> None:
        self._by_key: dict[tuple[str, str], NetworkRange] = {}

    async def save(self, network_range: NetworkRange) -> None:
        key = (str(network_range.tenant_id), str(network_range.range_id))
        self._by_key[key] = network_range

    async def get(self, tenant_id: TenantId, range_id: NetworkRangeId) -> NetworkRange | None:
        network_range = self._by_key.get((str(tenant_id), str(range_id)))
        if network_range is None or network_range.tenant_id != tenant_id:
            return None
        return network_range

    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[NetworkRange]:
        results = [r for (tid, _), r in self._by_key.items() if tid == str(tenant_id)]
        for field_name, value in filters.items():
            results = [r for r in results if getattr(r, field_name) == value]
        return tuple(results)


class FakeUnitOfWork:
    """An in-memory fake structurally satisfying `IUnitOfWork` (async
    commit/rollback, bundled repository attributes) — local to tests
    only, matching the platform-wide `IUnitOfWork` shape."""

    def __init__(
        self,
        assets: FakeAssetRepository,
        network_ranges: FakeNetworkRangeRepository,
    ) -> None:
        self.assets = assets
        self.network_ranges = network_ranges
        self._committed = False
        self.committed = 0
        self.rolled_back = 0

    async def commit(self) -> None:
        self._committed = True
        self.committed += 1

    async def rollback(self) -> None:
        self.rolled_back += 1

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: object,
    ) -> None:
        if not self._committed:
            await self.rollback()


@pytest.fixture
def tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def other_tenant_id() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def asset_repository() -> FakeAssetRepository:
    return FakeAssetRepository()


@pytest.fixture
def network_range_repository() -> FakeNetworkRangeRepository:
    return FakeNetworkRangeRepository()


@pytest.fixture
def unit_of_work(
    asset_repository: FakeAssetRepository,
    network_range_repository: FakeNetworkRangeRepository,
) -> FakeUnitOfWork:
    return FakeUnitOfWork(asset_repository, network_range_repository)


@pytest.fixture
def now() -> datetime:
    return datetime.now(UTC)


@pytest.fixture
def domain_name() -> DomainName:
    return DomainName("example.com")
