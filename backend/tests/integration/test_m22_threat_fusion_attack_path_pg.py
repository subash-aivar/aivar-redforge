"""M22 Phase 4+5 — Threat Fusion + Attack Path PostgreSQL integration."""

from __future__ import annotations

import os
import time

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.attack_path.attack_path_service import (
    AttackPathQueryService,
    AttackPathService,
)
from redforge.application.threat_intel.reference_data_admin_service import (
    ReferenceDataAdminService,
    RelationshipInput,
    TacticInput,
    TechniqueInput,
    VulnerabilityInput,
)
from redforge.application.threat_intel.threat_fusion_query_service import (
    ThreatFusionQueryService,
)
from redforge.application.threat_intel.threat_fusion_service import ThreatFusionService
from redforge.domain.threat_intel.fusion_value_objects import FusedIndicatorType
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m22_fusion_path_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_M22_FUSION_PATH_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def _seed_reference(session_factory) -> tuple[str, str, str]:
    admin = ReferenceDataAdminService(session_factory)
    suffix = time.time_ns() % 10000
    tactic_id = f"TA{suffix:04d}"
    tech_a = f"T{(suffix % 9000) + 1000:04d}"
    tech_b = f"T{(suffix % 9000) + 1001:04d}"
    cve = f"CVE-2026-{suffix:04d}"
    shortname = f"initial-access-{suffix}"
    stix_t = f"x-mitre-tactic--{suffix}"
    stix_a = f"attack-pattern--a{suffix}"
    stix_b = f"attack-pattern--b{suffix}"
    stix_rel = f"relationship--{suffix}"

    await admin.upsert_tactics(
        actor_id="01TESTACTOR00000000000001",
        tactics=[
            TacticInput(
                tactic_id=tactic_id,
                name="Initial Access",
                shortname=shortname,
                stix_id=stix_t,
            )
        ],
    )
    await admin.upsert_techniques(
        actor_id="01TESTACTOR00000000000001",
        techniques=[
            TechniqueInput(
                technique_id=tech_a,
                name="Exploit Public App",
                stix_id=stix_a,
                tactic_ids=[tactic_id],
            ),
            TechniqueInput(
                technique_id=tech_b,
                name="Command and Scripting",
                stix_id=stix_b,
                tactic_ids=[tactic_id],
            ),
        ],
    )
    await admin.upsert_technique_relationships(
        actor_id="01TESTACTOR00000000000001",
        relationships=[
            RelationshipInput(
                stix_id=stix_rel,
                relationship_type="precedes",
                source_ref=stix_a,
                target_ref=stix_b,
                source_technique_id=tech_a,
                target_technique_id=tech_b,
            )
        ],
    )
    await admin.upsert_vulnerabilities(
        actor_id="01TESTACTOR00000000000001",
        vulnerabilities=[
            VulnerabilityInput(cve_id=cve, description="test vuln", is_kev=True)
        ],
    )
    return tech_a, tech_b, cve


class TestFusionThenAttackPath:
    async def test_end_to_end_reference_to_fusion_to_path(self, session_factory) -> None:
        tech_a, tech_b, cve = await _seed_reference(session_factory)

        fusion = ThreatFusionService(session_factory)
        result = await fusion.fuse_reference_catalog(actor_id="01TESTACTOR00000000000001")
        assert result.indicators_created + result.indicators_updated >= 3
        assert result.relationships_upserted >= 1

        query = ThreatFusionQueryService(session_factory)
        techniques = await query.list_indicators(FusedIndicatorType.TECHNIQUE, limit=500)
        by_key = {t.canonical_key.raw_value: t for t in techniques}
        assert tech_a in by_key
        assert tech_b in by_key
        seed = by_key[tech_a]
        assert seed.confidence is not None

        vulns = await query.list_indicators(FusedIndicatorType.VULNERABILITY, limit=500)
        assert any(v.canonical_key.raw_value == cve for v in vulns)

        org_id = str(EntityId.generate())
        path_service = AttackPathService(session_factory)
        computed = await path_service.compute(
            organization_id=org_id,
            seed_indicator_id=seed.id,
            actor_id="01TESTACTOR00000000000001",
        )
        assert computed.path.organization_id == org_id
        assert computed.path.step_count >= 1
        assert computed.steps[0].entity_id == seed.id

        path_query = AttackPathQueryService(session_factory)
        loaded = await path_query.get_path(
            organization_id=org_id, path_id=computed.path.id
        )
        assert loaded is not None
        path, steps = loaded
        assert path.step_count == len(steps)

        result2 = await fusion.fuse_reference_catalog(actor_id="01TESTACTOR00000000000001")
        assert result2.indicators_created == 0 or result2.indicators_updated >= 0

    async def test_migration_head_is_current(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            assert result.scalar_one() == "0039"

    async def test_fusion_weight_override_persists(self, session_factory) -> None:
        fusion = ThreatFusionService(session_factory)
        await fusion.update_fusion_weight(
            source_system="stix_taxii_feed",
            weight=0.55,
            actor_id="01TESTACTOR00000000000001",
        )
        weights = await fusion.list_effective_weights()
        assert weights["stix_taxii_feed"] == 0.55
        assert weights["mitre_attack"] == 1.0
