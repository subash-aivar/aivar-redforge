"""Real-PostgreSQL concurrency proof for Security Graph projection — M4.

Proves the mandatory M4 concurrency invariants:
  1. Concurrent projection of the SAME (organization_id, source_domain,
     source_entity_id) node produces exactly one canonical graph node —
     enforced by `ux_sg_nodes_org_source` (migration 0014).
  2. Concurrent projection of the SAME edge key produces exactly one
     canonical edge — enforced by `ux_sg_edges_org_source_kind_target`.
  3. The same source entity identity across two DIFFERENT organizations
     produces two independent graph nodes.
  4. Cross-tenant edges are structurally impossible: a source/target
     node pair spanning two organizations is rejected by the database
     itself (composite foreign key), not merely application logic.

Runs against a dedicated, self-created database
(`redforge_security_graph_race_test`), never the shared dev database.
"""

from __future__ import annotations

import asyncio
import os

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.domain.security_graph.ontology import ONTOLOGY_VERSION
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.security_graph import (
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
)
from redforge.infrastructure.database.repositories.security_graph_repository import (
    SecurityGraphRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_security_graph_race_test"
_MAINTENANCE_DB_URL = os.environ.get(
    "REDFORGE_MAINTENANCE_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/postgres",
)
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)


async def _ensure_test_database_exists() -> None:
    maintenance_engine = create_async_engine(
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT",
    )
    try:
        async with maintenance_engine.connect() as conn:
            exists = await conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": _TEST_DB_NAME},
            )
            if exists.first() is None:
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(
            Base.metadata.create_all,
            tables=[SecurityGraphNodeModel.__table__, SecurityGraphEdgeModel.__table__],
        )
        # The ORM metadata (used by create_all here) does not carry the
        # tenant-scoped unique indexes — those are defined in migration
        # 0014 only, matching the M3 precedent
        # (test_asset_identity_race.py). Create them explicitly so this
        # test proves the SAME race-safety invariant migration 0014
        # enforces in production.
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_sg_nodes_org_source_test "
                "ON security_graph_nodes (organization_id, source_domain, source_entity_id)"
            )
        )
        await conn.execute(
            text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ux_sg_edges_org_source_kind_target_test "
                "ON security_graph_edges "
                "(organization_id, source_node_id, relationship_kind, target_node_id)"
            )
        )
        await conn.execute(text("DELETE FROM security_graph_edges"))
        await conn.execute(text("DELETE FROM security_graph_nodes"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS security_graph_edges CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_graph_nodes CASCADE"))
    await engine.dispose()


async def _upsert_node(pg_factory, organization_id: str, source_entity_id: str) -> str:
    async with SessionUnitOfWork(pg_factory) as uow:
        repo = SecurityGraphRepository(uow.session)
        node = await repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind="host",
            source_domain="asset",
            source_entity_id=source_entity_id,
            label="Concurrent Node",
            attributes={},
            ontology_version=ONTOLOGY_VERSION,
        )
        await uow.commit()
        return node.id


async def test_concurrent_same_source_produces_exactly_one_node(pg_factory):
    org_id = str(EntityId.generate())
    source_entity_id = str(EntityId.generate())

    results = await asyncio.gather(
        *(_upsert_node(pg_factory, org_id, source_entity_id) for _ in range(10))
    )

    assert len(set(results)) == 1, f"expected 1 unique node id, got {set(results)}"

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityGraphNodeModel.id)).where(
                SecurityGraphNodeModel.organization_id == org_id,
            )
        )
        count = result.scalar_one()
    assert count == 1, f"expected exactly 1 persisted node row, found {count}"


async def test_same_source_entity_across_orgs_remains_separate(pg_factory):
    source_entity_id = str(EntityId.generate())
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())

    results = await asyncio.gather(
        *(_upsert_node(pg_factory, org_a, source_entity_id) for _ in range(5)),
        *(_upsert_node(pg_factory, org_b, source_entity_id) for _ in range(5)),
    )

    a_ids = {r for i, r in enumerate(results) if i < 5}
    b_ids = {r for i, r in enumerate(results) if i >= 5}
    assert len(a_ids) == 1
    assert len(b_ids) == 1
    assert a_ids != b_ids

    async with pg_factory() as session:
        result = await session.execute(select(func.count(SecurityGraphNodeModel.id)))
        total = result.scalar_one()
    assert total == 2


async def test_concurrent_same_edge_produces_exactly_one_edge(pg_factory):
    org_id = str(EntityId.generate())
    source_node_id = await _upsert_node(pg_factory, org_id, "source-entity")
    target_node_id = await _upsert_node(pg_factory, org_id, "target-entity")

    async def upsert_edge() -> str:
        async with SessionUnitOfWork(pg_factory) as uow:
            repo = SecurityGraphRepository(uow.session)
            edge = await repo.upsert_edge(
                edge_id=str(EntityId.generate()),
                organization_id=org_id,
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                relationship_kind="custom",
                provenance="test",
                ontology_version=ONTOLOGY_VERSION,
            )
            await uow.commit()
            return edge.id

    results = await asyncio.gather(*(upsert_edge() for _ in range(10)))
    assert len(set(results)) == 1, f"expected 1 unique edge id, got {set(results)}"

    async with pg_factory() as session:
        result = await session.execute(
            select(func.count(SecurityGraphEdgeModel.id)).where(
                SecurityGraphEdgeModel.organization_id == org_id,
            )
        )
        count = result.scalar_one()
    assert count == 1, f"expected exactly 1 persisted edge row, found {count}"


async def test_cross_tenant_edge_rejected_by_database(pg_factory):
    """A source/target node pair spanning two organizations must be
    physically rejected by the database — the composite foreign key
    `fk_sg_edges_source_same_tenant`/`_target_same_tenant` requires
    (node_id, organization_id) to match, so an edge claiming
    organization_id=org_a but referencing org_b's node cannot be
    inserted at all."""
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    node_a = await _upsert_node(pg_factory, org_a, "entity-a")
    node_b = await _upsert_node(pg_factory, org_b, "entity-b")

    async with SessionUnitOfWork(pg_factory) as uow:
        repo = SecurityGraphRepository(uow.session)
        with pytest.raises(IntegrityError):
            await repo.upsert_edge(
                edge_id=str(EntityId.generate()),
                organization_id=org_a,
                source_node_id=node_a,
                target_node_id=node_b,  # belongs to org_b, not org_a
                relationship_kind="custom",
                provenance="test",
                ontology_version=ONTOLOGY_VERSION,
            )
