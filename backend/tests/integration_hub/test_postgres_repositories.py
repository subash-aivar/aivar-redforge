"""Integration tests for integration_hub's Postgres repositories."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.aggregates.sync_run import SyncRun
from integration_hub.domain.exceptions.domain_exceptions import ConcurrencyConflictError
from integration_hub.domain.value_objects.discovery import (
    AssetCategory,
    AssetIdentity,
    AssetRelationship,
    RelationshipType,
    SyncMode,
    VendorType,
)
from integration_hub.domain.value_objects.enums import (
    ConnectorHealthStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import ConnectorId, EntityId
from integration_hub.infrastructure.persistence.postgres_repositories import (
    PgConnectorHealthRecordRepository,
    PgConnectorRegistrationRepository,
    PgDiscoveredAssetRepository,
    PgSyncRunRepository,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("TEST_DATABASE_URL"), reason="requires TEST_DATABASE_URL"
    ),
]

TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test",
)


@pytest.fixture
def session_factory() -> async_sessionmaker[AsyncSession]:
    engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.mark.asyncio
async def test_registration_save_get_and_healthy_filter(session_factory) -> None:
    repo = PgConnectorRegistrationRepository(session_factory)
    tenant_id = EntityId(uuid7())

    connector_type = next(iter(ConnectorType))
    reg = ConnectorRegistration.register(
        tenant_id,
        connector_type,
        "SOC ticketing",
        "vault-key-1",
        "api_key",
        base_url="https://example.internal",
    )
    await repo.save(reg, tenant_id)

    fetched = await repo.get(reg.connector_id, tenant_id)
    assert fetched is not None
    assert fetched.display_name == "SOC ticketing"
    assert fetched.credential_ref.vault_key == "vault-key-1"
    assert fetched.status.value == "REGISTERED"

    healthy = await repo.find_healthy_for_action_type(tenant_id, connector_type)
    assert any(str(r.connector_id) == str(reg.connector_id) for r in healthy)

    reg.disable(tenant_id, "admin-1", "rotated credentials")
    await repo.save(reg, tenant_id)

    still_healthy = await repo.find_healthy_for_action_type(tenant_id, connector_type)
    assert not any(str(r.connector_id) == str(reg.connector_id) for r in still_healthy)

    all_for_tenant = await repo.find_all_for_tenant(tenant_id)
    assert len(all_for_tenant) == 1
    assert all_for_tenant[0].status.value == "DISABLED"


@pytest.mark.asyncio
async def test_health_records_append_and_find_latest(session_factory) -> None:
    repo = PgConnectorHealthRecordRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    first = ConnectorHealthRecord.create(
        tenant_id, connector_id, ConnectorHealthStatus.HEALTHY, 120, None, datetime.now(UTC)
    )
    await repo.append(first, tenant_id)
    second = ConnectorHealthRecord.create(
        tenant_id, connector_id, ConnectorHealthStatus.DEGRADED, 900, "slow response", datetime.now(UTC)
    )
    await repo.append(second, tenant_id)

    latest = await repo.find_latest_for_connector(connector_id, tenant_id, limit=10)
    assert len(latest) == 2
    assert latest[0].status.value == "DEGRADED"


@pytest.mark.asyncio
async def test_discovered_asset_save_get_relationships_and_filters(session_factory) -> None:
    repo = PgDiscoveredAssetRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    identity = AssetIdentity(
        vendor=VendorType.OPENAI, external_id="model-abc", tenant_id=str(tenant_id)
    )
    asset = DiscoveredAsset.discover(
        tenant_id,
        connector_id,
        identity,
        "gpt-test-model",
        AssetCategory.AI_MODEL,
        VendorType.OPENAI,
        region="us-east-1",
        owner="team-a",
        tags={"env": "prod"},
        metadata={"note": "seed"},
        configuration={"max_tokens": 4096},
    )
    asset.add_relationship(
        AssetRelationship(
            relationship_type=RelationshipType.DEPENDS_ON,
            target_external_id="model-dep-1",
        )
    )
    await repo.save(asset, tenant_id)

    fetched = await repo.get(asset.asset_id, tenant_id)
    assert fetched is not None
    assert fetched.name == "gpt-test-model"
    assert fetched.tags == {"env": "prod"}
    assert len(fetched.relationships) == 1
    assert fetched.relationships[0].target_external_id == "model-dep-1"

    by_fp = await repo.get_by_fingerprint(identity.fingerprint, tenant_id)
    assert by_fp is not None
    assert by_fp.asset_id == asset.asset_id

    for_connector = await repo.find_all_for_connector(connector_id, tenant_id)
    assert len(for_connector) == 1

    filtered = await repo.find_all_for_tenant(tenant_id, category="AI_MODEL", vendor="OPENAI")
    assert len(filtered) == 1
    no_match = await repo.find_all_for_tenant(tenant_id, category="AI_DEPLOYMENT")
    assert no_match == []

    # apply_sync + resave replaces relationship set and bumps version
    asset.apply_sync(
        name="gpt-test-model-v2",
        region="us-west-2",
        owner="team-a",
        tags={"env": "prod"},
        metadata={"note": "seed"},
        configuration={"max_tokens": 8192},
    )
    asset.remove_relationship(RelationshipType.DEPENDS_ON, "model-dep-1")
    await repo.save(asset, tenant_id)
    resynced = await repo.get(asset.asset_id, tenant_id)
    assert resynced is not None
    assert resynced.name == "gpt-test-model-v2"
    assert resynced.relationships == []

    await repo.delete(asset.asset_id, tenant_id)
    assert await repo.get(asset.asset_id, tenant_id) is None


@pytest.mark.asyncio
async def test_discovered_asset_optimistic_concurrency_conflict(session_factory) -> None:
    repo = PgDiscoveredAssetRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()
    identity = AssetIdentity(
        vendor=VendorType.ANTHROPIC, external_id="claude-1", tenant_id=str(tenant_id)
    )
    asset = DiscoveredAsset.discover(
        tenant_id, connector_id, identity, "claude-1", AssetCategory.AI_MODEL, VendorType.ANTHROPIC
    )
    await repo.save(asset, tenant_id)

    # Simulate two concurrent readers loading the same version, then both
    # attempting to write — the second write must lose with a conflict.
    reader_a = await repo.get(asset.asset_id, tenant_id)
    reader_b = await repo.get(asset.asset_id, tenant_id)
    assert reader_a is not None and reader_b is not None

    reader_a.apply_sync(
        name="claude-1-a",
        region=None,
        owner=None,
        tags={},
        metadata={},
        configuration={"x": 1},
    )
    await repo.save(reader_a, tenant_id)

    reader_b.apply_sync(
        name="claude-1-b",
        region=None,
        owner=None,
        tags={},
        metadata={},
        configuration={"x": 2},
    )
    with pytest.raises(ConcurrencyConflictError):
        await repo.save(reader_b, tenant_id)


@pytest.mark.asyncio
async def test_sync_run_save_and_find_for_connector(session_factory) -> None:
    repo = PgSyncRunRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    run = SyncRun.start(tenant_id, connector_id, SyncMode.FULL)
    await repo.save(run, tenant_id)
    run.complete(discovered=5, created=3, updated=2, deleted=0)
    await repo.save(run, tenant_id)

    runs = await repo.find_for_connector(connector_id, tenant_id, limit=10)
    assert len(runs) == 1
    assert runs[0].status.value == "COMPLETED"


@pytest.mark.asyncio
async def test_sync_run_checkpoint_cursor_and_pages_persist(session_factory) -> None:
    """Phase 2C: cursor/pages_processed are real persisted columns, not
    just in-memory state lost on crash/restart."""
    repo = PgSyncRunRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    run = SyncRun.start(tenant_id, connector_id, SyncMode.FULL)
    await repo.save(run, tenant_id)
    run.record_page(cursor="page-2-token", discovered=10, created=8, updated=2)
    await repo.save(run, tenant_id)

    reloaded = await repo.get(run.sync_run_id, tenant_id)
    assert reloaded is not None
    assert reloaded.cursor == "page-2-token"
    assert reloaded.pages_processed == 1
    assert reloaded.items_discovered == 10

    running = await repo.find_running_for_connector(connector_id, tenant_id)
    assert running is not None
    assert running.sync_run_id == run.sync_run_id

    run.complete(discovered=20, created=15, updated=5, deleted=0)
    await repo.save(run, tenant_id)
    assert await repo.find_running_for_connector(connector_id, tenant_id) is None


@pytest.mark.asyncio
async def test_tag_filter_pushed_into_sql_and_pagination_works(session_factory) -> None:
    """P0-3: the `tag` filter is a JSONB `?` (has_key) predicate evaluated
    in Postgres, not a Python-side loop after fetching every row, and
    find_all_for_tenant supports limit/offset/order_by."""
    repo = PgDiscoveredAssetRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    for i in range(5):
        identity = AssetIdentity(
            vendor=VendorType.OPENAI, external_id=f"model-{i}", tenant_id=str(tenant_id)
        )
        asset = DiscoveredAsset.discover(
            tenant_id,
            connector_id,
            identity,
            f"model-{i}",
            AssetCategory.AI_MODEL,
            VendorType.OPENAI,
            tags={"prod": "true"} if i % 2 == 0 else {"staging": "true"},
        )
        await repo.save(asset, tenant_id)

    prod_only = await repo.find_all_for_tenant(tenant_id, tag="prod")
    assert len(prod_only) == 3
    assert all("prod" in a.tags for a in prod_only)

    staging_only = await repo.find_all_for_tenant(tenant_id, tag="staging")
    assert len(staging_only) == 2

    page1 = await repo.find_all_for_tenant(tenant_id, limit=2, offset=0)
    page2 = await repo.find_all_for_tenant(tenant_id, limit=2, offset=2)
    assert len(page1) == 2
    assert len(page2) == 2
    assert {a.asset_id for a in page1}.isdisjoint({a.asset_id for a in page2})


@pytest.mark.asyncio
async def test_relationships_batch_loaded_for_a_page_of_assets(session_factory) -> None:
    """P0-3: relationships for a page of assets are loaded with one
    `WHERE source_asset_id IN (...)` query via
    find_relationships_for_assets, not one query per asset."""
    repo = PgDiscoveredAssetRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    asset_ids = []
    for i in range(3):
        identity = AssetIdentity(
            vendor=VendorType.OPENAI, external_id=f"rel-model-{i}", tenant_id=str(tenant_id)
        )
        asset = DiscoveredAsset.discover(
            tenant_id, connector_id, identity, f"rel-model-{i}", AssetCategory.AI_MODEL, VendorType.OPENAI
        )
        asset.add_relationship(
            AssetRelationship(
                relationship_type=RelationshipType.DEPENDS_ON,
                target_external_id=f"dep-{i}",
            )
        )
        await repo.save(asset, tenant_id)
        asset_ids.append(asset.asset_id)

    by_asset = await repo.find_relationships_for_assets(asset_ids, tenant_id)
    assert len(by_asset) == 3
    for asset_id in asset_ids:
        assert len(by_asset[asset_id]) == 1


@pytest.mark.asyncio
async def test_get_by_fingerprints_and_save_many_bulk_operations(session_factory) -> None:
    """P0-1/P0-3: the discovery loop's per-page batching primitives --
    bulk fingerprint lookup and bulk save in one session/commit."""
    repo = PgDiscoveredAssetRepository(session_factory)
    tenant_id = EntityId(uuid7())
    connector_id = ConnectorId.generate()

    assets = []
    fingerprints = []
    for i in range(4):
        identity = AssetIdentity(
            vendor=VendorType.OPENAI, external_id=f"bulk-{i}", tenant_id=str(tenant_id)
        )
        asset = DiscoveredAsset.discover(
            tenant_id, connector_id, identity, f"bulk-{i}", AssetCategory.AI_MODEL, VendorType.OPENAI
        )
        assets.append(asset)
        fingerprints.append(identity.fingerprint)

    await repo.save_many(assets, tenant_id)

    found = await repo.get_by_fingerprints(fingerprints, tenant_id)
    assert len(found) == 4
    assert all(fp in found for fp in fingerprints)

    # save_many again with the same asset_ids should update, not duplicate.
    for asset in assets:
        asset.apply_sync(
            name=asset.name + "-v2",
            region=None,
            owner=None,
            tags={},
            metadata={},
            configuration={},
        )
    await repo.save_many(assets, tenant_id)
    for_connector = await repo.find_all_for_connector(connector_id, tenant_id)
    assert len(for_connector) == 4
    assert all(a.name.endswith("-v2") for a in for_connector)


@pytest.mark.asyncio
async def test_entity_id_round_trip_through_postgres_read_path(session_factory) -> None:
    """P0-2: EntityId.from_uuid(row.tenant_id) round-tripped through a
    real Postgres UUID column is `==` to an EntityId built directly via
    `.generate()`/`.from_string()` on the same underlying value -- closing
    the 'different runtime shape' gap the audit flagged."""
    repo = PgConnectorRegistrationRepository(session_factory)
    generated = EntityId.generate()

    connector_type = next(iter(ConnectorType))
    reg = ConnectorRegistration.register(
        generated,
        connector_type,
        "round-trip test",
        "vault-key-round-trip",
        "api_key",
    )
    await repo.save(reg, generated)

    fetched = await repo.get(reg.connector_id, generated)
    assert fetched is not None
    # fetched.tenant_id was built inside the repository via
    # EntityId.from_uuid(row.tenant_id) -- must equal the EntityId this
    # test generated directly, not just look similar when printed.
    assert fetched.tenant_id == generated
    assert str(fetched.tenant_id) == str(generated)
    assert hash(fetched.tenant_id) == hash(generated)
