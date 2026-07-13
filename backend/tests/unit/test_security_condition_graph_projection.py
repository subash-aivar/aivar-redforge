"""SecurityGraphProjector.project_security_condition() proof — M8.

Covers: idempotent repeated projection, no raw evidence/secret reaches
graph attributes, ontology rejects an unsupported source pairing.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.security_graph.projector import SecurityGraphProjector
from redforge.domain.security_graph.ontology import NodeKind
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.security_graph import (
    SecurityGraphEdgeModel,
    SecurityGraphNodeModel,
)
from redforge.infrastructure.database.repositories.security_graph_repository import (
    SecurityGraphRepository,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio


@pytest.fixture
async def factory():
    engine = create_async_engine("sqlite+aiosqlite://", echo=False)
    async with engine.begin() as conn:
        # Excludes tables using raw postgresql.JSONB (platform_events,
        # platform_snapshots, platform_read_models, dead_letter_entries)
        # — those don't compile against SQLite. A whole-metadata
        # create_all() only "worked" before by luck of import order (this
        # test never touches those tables); scoping explicitly makes it
        # correct regardless of what else has been imported this session.
        sqlite_safe_tables = [
            t for t in Base.metadata.sorted_tables
            if t.name not in {
                "platform_events", "platform_snapshots",
                "platform_read_models", "dead_letter_entries",
            }
        ]
        await conn.run_sync(Base.metadata.create_all, tables=sqlite_safe_tables)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


async def test_condition_projection_creates_node_and_edge(factory) -> None:
    org_id = str(EntityId.generate())
    asset_id = str(EntityId.generate())
    condition_id = str(EntityId.generate())

    async with factory() as session:
        repo = SecurityGraphRepository(session)
        projector = SecurityGraphProjector(repo)
        await projector.project_asset(org_id, asset_id, "host", "test-host")
        node_id = await projector.project_security_condition(
            organization_id=org_id, condition_id=condition_id, affected_asset_id=asset_id,
            stable_rule_id="SENSITIVE_SERVICE_OBSERVED", title="Sensitive service observed",
            severity="medium", evidence_state="observed",
        )
        await session.commit()
        assert node_id is not None

        node = await repo.get_node_by_source_for_org(org_id, "security_condition", condition_id)
        assert node is not None
        assert node.node_kind == NodeKind.SECURITY_CONDITION.value

        edge_count = await session.execute(select(func.count(SecurityGraphEdgeModel.id)))
        assert edge_count.scalar_one() == 1


async def test_repeated_projection_is_idempotent(factory) -> None:
    org_id = str(EntityId.generate())
    asset_id = str(EntityId.generate())
    condition_id = str(EntityId.generate())

    async with factory() as session:
        repo = SecurityGraphRepository(session)
        projector = SecurityGraphProjector(repo)
        await projector.project_asset(org_id, asset_id, "host", "test-host")
        for _ in range(3):
            await projector.project_security_condition(
                organization_id=org_id, condition_id=condition_id, affected_asset_id=asset_id,
                stable_rule_id="SENSITIVE_SERVICE_OBSERVED", title="Sensitive service observed",
                severity="medium", evidence_state="observed",
            )
        await session.commit()

        node_count = await session.execute(select(func.count(SecurityGraphNodeModel.id)))
        edge_count = await session.execute(select(func.count(SecurityGraphEdgeModel.id)))
        assert node_count.scalar_one() == 2  # asset node + condition node
        assert edge_count.scalar_one() == 1


async def test_no_raw_evidence_or_secret_in_graph_attributes(factory) -> None:
    org_id = str(EntityId.generate())
    asset_id = str(EntityId.generate())
    condition_id = str(EntityId.generate())
    sentinel = "AKIASENTINELTEST0000"

    async with factory() as session:
        repo = SecurityGraphRepository(session)
        projector = SecurityGraphProjector(repo)
        await projector.project_asset(org_id, asset_id, "host", "test-host")
        await projector.project_security_condition(
            organization_id=org_id, condition_id=condition_id, affected_asset_id=asset_id,
            stable_rule_id="SENSITIVE_SERVICE_OBSERVED", title="Sensitive service observed",
            severity="medium", evidence_state="observed",
        )
        await session.commit()

        node = await repo.get_node_by_source_for_org(org_id, "security_condition", condition_id)
        assert sentinel not in str(node.attributes)
        assert set(node.attributes.keys()) == {"severity", "evidence_state", "stable_rule_id"}


async def test_unsupported_condition_source_pairing_rejected(factory) -> None:
    """A FINDING node is not in the HAS_SECURITY_CONDITION source set —
    projecting a condition against it must not fabricate an edge."""
    org_id = str(EntityId.generate())
    finding_asset_id = str(EntityId.generate())
    condition_id = str(EntityId.generate())

    async with factory() as session:
        repo = SecurityGraphRepository(session)
        projector = SecurityGraphProjector(repo)
        await repo.upsert_node(
            node_id=str(EntityId.generate()), organization_id=org_id,
            node_kind=NodeKind.FINDING.value, source_domain="asset",
            source_entity_id=finding_asset_id, label="not-a-real-asset", attributes={},
            ontology_version=5,
        )
        node_id = await projector.project_security_condition(
            organization_id=org_id, condition_id=condition_id, affected_asset_id=finding_asset_id,
            stable_rule_id="SENSITIVE_SERVICE_OBSERVED", title="Sensitive service observed",
            severity="medium", evidence_state="observed",
        )
        await session.commit()
        assert node_id is not None

        edge_count = await session.execute(select(func.count(SecurityGraphEdgeModel.id)))
        assert edge_count.scalar_one() == 0
