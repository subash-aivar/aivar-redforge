"""Integration tests for PgNetworkRangeRepository."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_surface_management.domain.value_objects.enums import NetworkRangeLifecycleState
from attack_surface_management.domain.value_objects.identifiers import NetworkRangeId
from attack_surface_management.infrastructure.persistence.repositories.pg_network_range_repository import (
    PgNetworkRangeRepository,
)
from tests.attack_surface_management.infrastructure.helpers import (
    make_network_range,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_cold_session_reload_reads_from_a_fresh_identity_map(
    asm_session_factory,
) -> None:
    """`NetworkRange` has no owned child entities, so there is no
    `lazy="selectin"` relationship to regress on the way `Asset`'s
    four child collections can — but this still proves `get()` issues
    a genuine cold DB read rather than serving a cached row from a
    session-level identity map shared with the writer, by opening a
    brand-new `AsyncSession` against a range a *different*,
    already-closed session wrote and committed."""
    tenant_id = make_tenant_id()
    now = datetime.now(UTC)
    network_range = make_network_range(tenant_id, cidr="192.0.2.0/24", now=now)
    network_range.record_asset_count(tenant_id, 12, now)

    write_session = asm_session_factory()
    try:
        write_repo = PgNetworkRangeRepository(write_session)
        await write_repo.save(network_range)
        await write_session.commit()
    finally:
        await write_session.close()

    read_session = asm_session_factory()
    try:
        read_repo = PgNetworkRangeRepository(read_session)
        loaded = await read_repo.get(tenant_id, network_range.range_id)
        assert loaded is not None
        assert str(loaded.cidr) == "192.0.2.0/24"
        assert loaded.asset_count == 12
    finally:
        await read_session.rollback()
        await read_session.close()


@pytest.mark.asyncio
async def test_save_and_get_round_trip(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    network_range = make_network_range(tenant_id, cidr="10.1.0.0/16")

    await repo.save(network_range)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, network_range.range_id)
    assert loaded is not None
    assert loaded.range_id == network_range.range_id
    assert loaded.tenant_id == tenant_id
    assert str(loaded.cidr) == "10.1.0.0/16"
    assert loaded.lifecycle_state == NetworkRangeLifecycleState.DISCOVERED
    assert loaded.asset_count == 0


@pytest.mark.asyncio
async def test_get_returns_none_for_unknown_range(asm_session) -> None:
    repo = PgNetworkRangeRepository(asm_session)
    assert await repo.get(make_tenant_id(), NetworkRangeId.generate()) is None


@pytest.mark.asyncio
async def test_get_enforces_tenant_isolation(asm_session) -> None:
    owner_tenant = make_tenant_id()
    other_tenant = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    network_range = make_network_range(owner_tenant, cidr="10.2.0.0/16")
    await repo.save(network_range)
    await asm_session.commit()

    assert await repo.get(other_tenant, network_range.range_id) is None
    assert await repo.get(owner_tenant, network_range.range_id) is not None


@pytest.mark.asyncio
async def test_save_persists_lifecycle_transitions_and_asset_count(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    network_range = make_network_range(tenant_id, cidr="10.3.0.0/16")
    await repo.save(network_range)
    await asm_session.commit()

    now = datetime.now(UTC)
    network_range.activate(tenant_id, now)
    network_range.record_asset_count(tenant_id, 7, now)
    await repo.save(network_range)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, network_range.range_id)
    assert loaded is not None
    assert loaded.lifecycle_state == NetworkRangeLifecycleState.ACTIVE
    assert loaded.asset_count == 7


@pytest.mark.asyncio
async def test_list_filters_by_lifecycle_state(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    discovered = make_network_range(tenant_id, cidr="10.4.0.0/16")
    active = make_network_range(tenant_id, cidr="10.5.0.0/16")
    active.activate(tenant_id, datetime.now(UTC))
    await repo.save(discovered)
    await repo.save(active)
    await asm_session.commit()

    all_ranges = await repo.list(tenant_id)
    assert {r.range_id for r in all_ranges} == {discovered.range_id, active.range_id}

    only_active = await repo.list(tenant_id, lifecycle_state=NetworkRangeLifecycleState.ACTIVE)
    assert [r.range_id for r in only_active] == [active.range_id]


@pytest.mark.asyncio
async def test_list_supports_pagination(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    for i in range(5):
        await repo.save(make_network_range(tenant_id, cidr=f"10.{i}.0.0/16"))
    await asm_session.commit()

    page_1 = await repo.list(tenant_id, limit=2, offset=0)
    page_2 = await repo.list(tenant_id, limit=2, offset=2)
    assert len(page_1) == 2
    assert len(page_2) == 2
    assert {r.range_id for r in page_1}.isdisjoint({r.range_id for r in page_2})


@pytest.mark.asyncio
async def test_list_is_tenant_scoped(asm_session) -> None:
    tenant_a = make_tenant_id()
    tenant_b = make_tenant_id()
    repo = PgNetworkRangeRepository(asm_session)
    await repo.save(make_network_range(tenant_a, cidr="10.10.0.0/16"))
    await repo.save(make_network_range(tenant_b, cidr="10.20.0.0/16"))
    await asm_session.commit()

    assert len(await repo.list(tenant_a)) == 1
    assert len(await repo.list(tenant_b)) == 1
