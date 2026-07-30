"""Integration tests for PgAssetRepository."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.dns_record import DnsRecordEntry
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.value_objects.enums import (
    AssetLifecycleState,
    CertificateStatus,
    DnsRecordType,
    PortProtocol,
    PortState,
)
from attack_surface_management.domain.value_objects.identifiers import (
    AssetId,
    CertificateId,
    DnsRecordId,
    PortId,
)
from attack_surface_management.domain.value_objects.service_banner import ServiceBanner
from attack_surface_management.domain.value_objects.technology_fingerprint import (
    TechnologyFingerprint,
)
from attack_surface_management.infrastructure.persistence.repositories.pg_asset_repository import (
    PgAssetRepository,
)
from tests.attack_surface_management.infrastructure.helpers import (
    make_asset,
    make_asset_with_ip,
    make_tenant_id,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_cold_session_reload_exercises_selectin_relationship_loading(
    asm_session_factory,
) -> None:
    """Regression test for the `MissingGreenlet` class of bug: a
    single shared session across save+get within one test can serve
    `row.ports`/`row.certificates`/`row.dns_records`/`row.fingerprints`
    straight out of SQLAlchemy's session-level identity map without
    ever issuing a real lazy/eager-load query — which would let a
    regression (e.g. someone removing `lazy="selectin"` from the ORM
    models) pass unnoticed. This test opens a brand-new `AsyncSession`
    with an empty identity map to `get()` an asset that a *different*,
    already-closed session wrote and committed, forcing a genuine cold
    DB read of all four child relationships. Without
    `lazy="selectin"`, this raises `sqlalchemy.exc.MissingGreenlet`."""
    tenant_id = make_tenant_id()
    now = datetime.now(UTC)
    asset = make_asset(tenant_id, domain="cold-session.example.com", now=now)
    asset.add_port(
        tenant_id,
        OpenPort(
            port_id=PortId.generate(),
            port_number=443,
            protocol=PortProtocol.TCP,
            state=PortState.OPEN,
            detected_at=now,
            service=ServiceBanner(name="https", version="1.1"),
        ),
        now,
    )
    asset.add_certificate(
        tenant_id,
        Certificate(
            certificate_id=CertificateId.generate(),
            common_name="cold-session.example.com",
            issuer="Test CA",
            serial_number="abc123",
            not_before=now,
            not_after=now.replace(year=now.year + 1),
            status=CertificateStatus.VALID,
        ),
        now,
    )
    asset.add_dns_record(
        tenant_id,
        DnsRecordEntry(
            record_id=DnsRecordId.generate(),
            record_type=DnsRecordType.A,
            name="cold-session.example.com",
            value="203.0.113.1",
            ttl_seconds=300,
            detected_at=now,
        ),
        now,
    )
    asset.add_technology_fingerprint(
        tenant_id, TechnologyFingerprint(name="nginx", version="1.24.0", confidence=0.9), now
    )

    write_session = asm_session_factory()
    try:
        write_repo = PgAssetRepository(write_session)
        await write_repo.save(asset)
        await write_session.commit()
    finally:
        await write_session.close()

    # A fresh session/identity-map — nothing from the write above is
    # cached here. `get()` must issue real queries, including for all
    # four relationships, and must not raise MissingGreenlet.
    read_session = asm_session_factory()
    try:
        read_repo = PgAssetRepository(read_session)
        loaded = await read_repo.get(tenant_id, asset.asset_id)
        assert loaded is not None
        assert len(loaded.ports) == 1
        assert loaded.ports[0].port_number == 443
        assert loaded.ports[0].service is not None
        assert loaded.ports[0].service.name == "https"
        assert len(loaded.certificates) == 1
        assert loaded.certificates[0].common_name == "cold-session.example.com"
        assert len(loaded.dns_records) == 1
        assert loaded.dns_records[0].value == "203.0.113.1"
        assert len(loaded.fingerprints) == 1
        assert loaded.fingerprints[0].name == "nginx"
    finally:
        await read_session.rollback()
        await read_session.close()


@pytest.mark.asyncio
async def test_save_and_get_round_trip(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    asset = make_asset(tenant_id, domain="round-trip.example.com")

    await repo.save(asset)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, asset.asset_id)
    assert loaded is not None
    assert loaded.asset_id == asset.asset_id
    assert loaded.tenant_id == tenant_id
    assert loaded.domain_name is not None
    assert str(loaded.domain_name) == "round-trip.example.com"
    assert loaded.lifecycle_state == AssetLifecycleState.DISCOVERED
    assert loaded.ports == ()
    assert loaded.certificates == ()


@pytest.mark.asyncio
async def test_save_persists_ip_address_assets(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    asset = make_asset_with_ip(tenant_id, ip="198.51.100.7")

    await repo.save(asset)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, asset.asset_id)
    assert loaded is not None
    assert loaded.ip_address is not None
    assert str(loaded.ip_address) == "198.51.100.7"
    assert loaded.domain_name is None


@pytest.mark.asyncio
async def test_get_returns_none_for_unknown_asset(asm_session) -> None:
    repo = PgAssetRepository(asm_session)
    assert await repo.get(make_tenant_id(), AssetId.generate()) is None


@pytest.mark.asyncio
async def test_get_enforces_tenant_isolation(asm_session) -> None:
    owner_tenant = make_tenant_id()
    other_tenant = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    asset = make_asset(owner_tenant, domain="tenant-isolated.example.com")
    await repo.save(asset)
    await asm_session.commit()

    # An asset that exists under a different tenant must be
    # indistinguishable from "doesn't exist" — never leak existence.
    assert await repo.get(other_tenant, asset.asset_id) is None
    assert await repo.get(owner_tenant, asset.asset_id) is not None


@pytest.mark.asyncio
async def test_save_full_aggregate_reconstruction_with_children(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    now = datetime.now(UTC)
    asset = make_asset(tenant_id, domain="full-reconstruction.example.com", now=now)
    asset.add_port(
        tenant_id,
        OpenPort(
            port_id=PortId.generate(),
            port_number=22,
            protocol=PortProtocol.TCP,
            state=PortState.OPEN,
            detected_at=now,
        ),
        now,
    )
    asset.add_dns_record(
        tenant_id,
        DnsRecordEntry(
            record_id=DnsRecordId.generate(),
            record_type=DnsRecordType.TXT,
            name="full-reconstruction.example.com",
            value="v=spf1 -all",
            ttl_seconds=3600,
            detected_at=now,
        ),
        now,
    )

    await repo.save(asset)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, asset.asset_id)
    assert loaded is not None
    assert len(loaded.ports) == 1
    assert loaded.ports[0].port_number == 22
    assert loaded.ports[0].is_high_risk is False
    assert len(loaded.dns_records) == 1
    assert loaded.dns_records[0].record_type == DnsRecordType.TXT


@pytest.mark.asyncio
async def test_save_replaces_ports_on_reconciliation(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    now = datetime.now(UTC)
    asset = make_asset(tenant_id, domain="reconcile.example.com", now=now)
    port_id = PortId.generate()
    asset.add_port(
        tenant_id,
        OpenPort(
            port_id=port_id,
            port_number=80,
            protocol=PortProtocol.TCP,
            state=PortState.OPEN,
            detected_at=now,
        ),
        now,
    )
    await repo.save(asset)
    await asm_session.commit()

    asset.close_port(tenant_id, port_id, now)
    await repo.save(asset)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, asset.asset_id)
    assert loaded is not None
    assert len(loaded.ports) == 1
    assert loaded.ports[0].state == PortState.CLOSED


@pytest.mark.asyncio
async def test_save_persists_lifecycle_and_classification_transitions(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    asset = make_asset(tenant_id, domain="lifecycle.example.com")
    await repo.save(asset)
    await asm_session.commit()

    now = datetime.now(UTC)
    asset.transition_lifecycle(tenant_id, AssetLifecycleState.VALIDATED, now)
    await repo.save(asset)
    await asm_session.commit()

    loaded = await repo.get(tenant_id, asset.asset_id)
    assert loaded is not None
    assert loaded.lifecycle_state == AssetLifecycleState.VALIDATED


@pytest.mark.asyncio
async def test_list_filters_by_lifecycle_state_and_asset_type(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    discovered = make_asset(tenant_id, domain="filter-a.example.com")
    validated = make_asset(tenant_id, domain="filter-b.example.com")
    validated.transition_lifecycle(tenant_id, AssetLifecycleState.VALIDATED, datetime.now(UTC))
    await repo.save(discovered)
    await repo.save(validated)
    await asm_session.commit()

    all_assets = await repo.list(tenant_id)
    assert {a.asset_id for a in all_assets} == {discovered.asset_id, validated.asset_id}

    only_validated = await repo.list(tenant_id, lifecycle_state=AssetLifecycleState.VALIDATED)
    assert [a.asset_id for a in only_validated] == [validated.asset_id]

    only_external = await repo.list(tenant_id, asset_type=discovered.asset_type)
    assert discovered.asset_id in {a.asset_id for a in only_external}


@pytest.mark.asyncio
async def test_list_supports_pagination(asm_session) -> None:
    tenant_id = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    for i in range(5):
        await repo.save(make_asset(tenant_id, domain=f"page-{i}.example.com"))
    await asm_session.commit()

    page_1 = await repo.list(tenant_id, limit=2, offset=0)
    page_2 = await repo.list(tenant_id, limit=2, offset=2)
    assert len(page_1) == 2
    assert len(page_2) == 2
    assert {a.asset_id for a in page_1}.isdisjoint({a.asset_id for a in page_2})


@pytest.mark.asyncio
async def test_list_is_tenant_scoped(asm_session) -> None:
    tenant_a = make_tenant_id()
    tenant_b = make_tenant_id()
    repo = PgAssetRepository(asm_session)
    await repo.save(make_asset(tenant_a, domain="tenant-a.example.com"))
    await repo.save(make_asset(tenant_b, domain="tenant-b.example.com"))
    await asm_session.commit()

    assert len(await repo.list(tenant_a)) == 1
    assert len(await repo.list(tenant_b)) == 1
