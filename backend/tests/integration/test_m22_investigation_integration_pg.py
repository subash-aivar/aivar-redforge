"""M22 Phase 6 — Investigation Integration PostgreSQL proofs."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.investigations.case_service import InvestigationCaseService
from redforge.application.investigations.correlation_engine import evaluate_pair
from redforge.application.investigations.source_adapters import (
    adapt_behavior_detection,
    adapt_threat_intel_enrichment,
)
from redforge.application.threat_intel.sync_orchestration_service import (
    JOB_ATTACK_TECHNIQUE,
    ThreatIntelSyncOrchestrationService,
)
from redforge.application.threat_intel.threat_fusion_service import ThreatFusionService
from redforge.domain.investigations.value_objects import CorrelationRuleId
from redforge.infrastructure.database.models.threat_intel import (
    ThreatIntelEnrichmentModel,
    ThreatIntelIndicatorModel,
)
from redforge.infrastructure.database.repositories.investigations.case_repository import (
    SqlAlchemyEvidenceLinkRepository,
    SqlAlchemyInvestigationEventRepository,
    SqlAlchemyInvestigationRepository,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m22_investigation_integration_proof"
_DB_URL = os.environ.get(
    "REDFORGE_M22_INV_INT_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


class TestInvestigationIntegration:
    async def test_migration_head_is_0039(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            assert result.scalar_one() == "0039"

    async def test_ti_behavior_correlation_creates_case(self, session_factory) -> None:
        org_id = str(EntityId.generate())
        ip = "198.51.100.77"
        now = datetime.now(UTC)
        indicator_id = str(EntityId.generate())
        enrichment_id = str(EntityId.generate())

        async with session_factory() as session, session.begin():
            # Flush indicator first: composite FK on enrichments is declared
            # via ForeignKeyConstraint only, so SQLAlchemy may not order inserts.
            session.add(
                ThreatIntelIndicatorModel(
                    id=indicator_id,
                    organization_id=org_id,
                    indicator=ip,
                    indicator_type="ip",
                    first_seen_at=now,
                    last_seen_at=now,
                )
            )
            await session.flush()
            session.add(
                ThreatIntelEnrichmentModel(
                    id=enrichment_id,
                    organization_id=org_id,
                    indicator_id=indicator_id,
                    provider_name="abuseipdb",
                    kind="reputation",
                    success=True,
                    error_category=None,
                    data={"confidence_score": 88.0},
                    detail="",
                    fetched_at=now,
                    expires_at=now + timedelta(hours=3),
                )
            )

        ti = adapt_threat_intel_enrichment(
            org_id,
            indicator_id=indicator_id,
            indicator=ip,
            indicator_type="ip",
            enrichment_id=enrichment_id,
            provider_name="abuseipdb",
            kind="reputation",
            success=True,
            data={"confidence_score": 88.0},
            fetched_at=now,
            expires_at=now + timedelta(hours=3),
            now=now,
        )
        beh = adapt_behavior_detection(
            org_id=org_id,
            detection_id=str(EntityId.generate()),
            correlation_key="beh-ti-1",
            entity_type="IP_ADDRESS",
            entity_id=ip,
            detection_type="C2",
            severity="HIGH",
            status="OPEN",
            evidence={},
            secondary_entity_id=None,
            detected_at=now,
        )
        assert ti is not None and beh is not None
        decision = evaluate_pair(ti, beh)
        assert decision is not None
        assert decision.rule_id is CorrelationRuleId.THREAT_INTEL_ENRICHMENT

        async with session_factory() as session, session.begin():
            svc = InvestigationCaseService(
                session,
                SqlAlchemyInvestigationRepository(session),
                SqlAlchemyEvidenceLinkRepository(session),
                SqlAlchemyInvestigationEventRepository(session),
            )
            result = await svc.correlate_pair(ti, beh)
        assert result is not None
        assert result["created"] is True

    async def test_sync_status_and_fusion_trigger(self, session_factory) -> None:
        service = ThreatIntelSyncOrchestrationService(
            session_factory,
            fusion_service=ThreatFusionService(session_factory),
        )
        status = await service.list_status()
        keys = {s.job_key for s in status}
        assert JOB_ATTACK_TECHNIQUE in keys
        payload = await service.run_attack_technique_sync(
            actor_id="01TESTACTOR00000000000001"
        )
        assert "fusion" in payload
        status_after = await service.list_status()
        tech = next(s for s in status_after if s.job_key == JOB_ATTACK_TECHNIQUE)
        assert tech.last_status in {"succeeded", "failed"}
