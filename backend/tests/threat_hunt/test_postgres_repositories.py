"""Integration tests for threat_hunt's Postgres repositories."""

from __future__ import annotations

import os
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    TenantId,
)
from threat_hunt.infrastructure.persistence.postgres_repositories import (
    PgThreatHuntCandidateRepository,
    PgThreatHuntConfigurationRepository,
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
async def test_save_find_by_id_and_pending_review(session_factory) -> None:
    repo = PgThreatHuntCandidateRepository(session_factory)
    tenant_id = TenantId(uuid7())

    candidate = ThreatHuntCandidate.create(
        tenant_id,
        (AnomalySignalRef(signal_id="sig-1", source="m33"),),
        (AttckTechniqueRef(technique_id="T1059", name="Command and Scripting Interpreter"),),
        "title contains beacon; count() by src_ip",
        DetectionRuleFormat.SIGMA,
        0.82,
    )
    await repo.save(candidate, tenant_id)

    fetched = await repo.find_by_id(candidate.candidate_id.value, tenant_id)
    assert fetched is not None
    assert fetched.detection_logic_draft == candidate.detection_logic_draft
    assert len(fetched.anomaly_signal_refs) == 1
    assert fetched.anomaly_signal_refs[0].signal_id == "sig-1"
    assert len(fetched.technique_coverage) == 1
    assert fetched.technique_coverage[0].technique_id == "T1059"

    pending = await repo.find_pending_review(tenant_id, limit=10)
    assert any(str(c.candidate_id) == str(candidate.candidate_id) for c in pending)


@pytest.mark.asyncio
async def test_promote_removes_from_pending_review(session_factory) -> None:
    repo = PgThreatHuntCandidateRepository(session_factory)
    tenant_id = TenantId(uuid7())

    candidate = ThreatHuntCandidate.create(
        tenant_id,
        (AnomalySignalRef(signal_id="sig-2", source="m33"),),
        (),
        "detection logic",
        DetectionRuleFormat.KQL,
        0.6,
    )
    await repo.save(candidate, tenant_id)

    candidate.promote(tenant_id, "engineer-1", ("soc:detection_engineer",), uuid7())
    await repo.save(candidate, tenant_id)

    pending = await repo.find_pending_review(tenant_id, limit=10)
    assert not any(str(c.candidate_id) == str(candidate.candidate_id) for c in pending)

    fetched = await repo.find_by_id(candidate.candidate_id.value, tenant_id)
    assert fetched is not None
    assert fetched.candidate_status.value == "promoted"
    assert fetched.reviewed_by == "engineer-1"
    # anomaly_signal_refs are set once at creation and unaffected by promote()
    assert len(fetched.anomaly_signal_refs) == 1


@pytest.mark.asyncio
async def test_configuration_get_or_create_default_is_idempotent(session_factory) -> None:
    repo = PgThreatHuntConfigurationRepository(session_factory)
    tenant_id = TenantId(uuid7())

    first = await repo.get_or_create_default(tenant_id)
    assert first.min_signal_strength == 0.5
    assert first.enabled_signal_types == ["anomaly", "beaconing"]

    second = await repo.get_or_create_default(tenant_id)
    assert second.min_signal_strength == first.min_signal_strength
