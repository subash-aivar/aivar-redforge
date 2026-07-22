"""Integration tests for the Postgres-backed incident repositories.

Requires a live database migrated to head — set TEST_DATABASE_URL to run.
Skipped otherwise (same convention as tests/credential_vault/infrastructure).
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import uuid7

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from incident.domain.aggregates.containment_action import ContainmentAction
from incident.domain.aggregates.eradication_verification import EradicationVerification
from incident.domain.aggregates.incident import Incident
from incident.domain.aggregates.recovery_milestone import RecoveryMilestone
from incident.domain.entities.communication_log_entry import IncidentCommunicationLogEntry
from incident.domain.value_objects.enums import (
    CommunicationType,
    ContainmentActionType,
    ContainmentAuthorizationLevel,
    IncidentSeverity,
    IncidentTriggerType,
    SeverityClassificationMethod,
)
from incident.domain.value_objects.identifiers import (
    CommunicationLogEntryId,
    ContainmentActionId,
    EradicationVerificationId,
    IncidentId,
    RecoveryMilestoneId,
    TenantId,
)
from incident.domain.value_objects.refs import (
    EradicationEvidenceRef,
    EscalatedFindingRef,
    ExposureScopeRef,
    InvestigationRef,
)
from incident.infrastructure.persistence.postgres_repositories import (
    PgContainmentActionRepository,
    PgEradicationVerificationRepository,
    PgIncidentCommunicationLogRepository,
    PgIncidentRepository,
    PgRecoveryMilestoneRepository,
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


def _now() -> datetime:
    return datetime.now(UTC)


@pytest.mark.asyncio
async def test_incident_save_and_find_round_trip(session_factory) -> None:
    repo = PgIncidentRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = IncidentId(uuid7())
    now = _now()

    incident = Incident.declare(
        incident_id,
        tenant_id,
        "Suspicious lateral movement",
        "EDR flagged anomalous SMB traffic between hosts",
        IncidentTriggerType.DETECTION_FINDING,
        IncidentSeverity.P2_HIGH,
        now,
        source_finding_ref=EscalatedFindingRef(
            finding_id="finding-1",
            severity="high",
            asset_ref="asset-1",
            rule_id="rule-42",
            detected_at=now,
            escalated_by="analyst-1",
        ),
        investigation_ref=InvestigationRef(
            investigation_id="inv-1", concluded_at=None, conclusion=""
        ),
    )
    incident.exposure_scope_refs.append(
        ExposureScopeRef(asset_ref_id="asset-1", composite_score=7.5, assessed_at=now)
    )
    incident.classify(
        tenant_id,
        IncidentSeverity.P1_CRITICAL,
        SeverityClassificationMethod.MANUAL_DECLARATION,
        now,
        "commander-1",
    )

    await repo.save(tenant_id, incident)

    fetched = await repo.find_by_id(tenant_id, incident_id)
    assert fetched is not None
    assert fetched.title == incident.title
    assert fetched.severity == IncidentSeverity.P1_CRITICAL
    assert fetched.classification_method == SeverityClassificationMethod.MANUAL_DECLARATION
    assert fetched.version == incident.version
    assert len(fetched.timeline) == len(incident.timeline)
    assert fetched.source_finding_ref is not None
    assert fetched.source_finding_ref.finding_id == "finding-1"
    assert fetched.investigation_ref is not None
    assert fetched.investigation_ref.investigation_id == "inv-1"
    assert len(fetched.exposure_scope_refs) == 1
    assert fetched.exposure_scope_refs[0].asset_ref_id == "asset-1"

    active = await repo.find_active(tenant_id)
    assert any(str(i.incident_id) == str(incident_id) for i in active)

    by_severity = await repo.find_by_severity(tenant_id, IncidentSeverity.P1_CRITICAL)
    assert any(str(i.incident_id) == str(incident_id) for i in by_severity)


@pytest.mark.asyncio
async def test_incident_tags_and_timeline_survive_resave(session_factory) -> None:
    repo = PgIncidentRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = IncidentId(uuid7())
    now = _now()

    incident = Incident.declare(
        incident_id,
        tenant_id,
        "Credential stuffing burst",
        "Auth service saw 40x baseline failed logins",
        IncidentTriggerType.MANUAL_DECLARATION,
        IncidentSeverity.P3_MEDIUM,
        now,
    )
    await repo.save(tenant_id, incident)

    incident.classify(
        tenant_id,
        IncidentSeverity.P2_HIGH,
        SeverityClassificationMethod.MANUAL_DECLARATION,
        now,
        "commander-1",
    )
    await repo.save(tenant_id, incident)

    fetched = await repo.find_by_id(tenant_id, incident_id)
    assert fetched is not None
    # Two phase transitions: declare + classify — re-saving must not
    # duplicate or lose timeline rows from the earlier save.
    assert len(fetched.timeline) == 2


@pytest.mark.asyncio
async def test_containment_action_round_trip(session_factory) -> None:
    repo = PgContainmentActionRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = IncidentId(uuid7())
    action_id = ContainmentActionId(uuid7())

    action = ContainmentAction.request(
        action_id,
        tenant_id,
        incident_id,
        ContainmentActionType.NETWORK_ISOLATION,
        "Isolate host from network",
        ContainmentAuthorizationLevel.COMMANDER,
    )
    await repo.save(tenant_id, action)

    action.authorize(tenant_id, "commander-1", _now())
    await repo.save(tenant_id, action)

    fetched = await repo.find_by_id(tenant_id, action_id)
    assert fetched is not None
    assert fetched.authorized_by == "commander-1"

    by_incident = await repo.find_by_incident(tenant_id, incident_id)
    assert len(by_incident) == 1


@pytest.mark.asyncio
async def test_eradication_verification_round_trip(session_factory) -> None:
    repo = PgEradicationVerificationRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = IncidentId(uuid7())
    verification_id = EradicationVerificationId(uuid7())

    verification = EradicationVerification.submit(
        verification_id,
        tenant_id,
        incident_id,
        "Malware removed and host reimaged",
        [EradicationEvidenceRef(evidence_id="ev-1", description="scan report")],
        "analyst-1",
        _now(),
    )
    await repo.save(tenant_id, verification)

    fetched = await repo.find_by_incident(tenant_id, incident_id)
    assert fetched is not None
    assert fetched.assertion == verification.assertion
    assert len(fetched.evidence_refs) == 1
    assert fetched.evidence_refs[0].evidence_id == "ev-1"


@pytest.mark.asyncio
async def test_recovery_milestone_round_trip(session_factory) -> None:
    repo = PgRecoveryMilestoneRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = IncidentId(uuid7())
    milestone_id = RecoveryMilestoneId(uuid7())

    milestone = RecoveryMilestone.create(
        milestone_id,
        tenant_id,
        incident_id,
        "Restore service",
        "Bring the affected service back online",
        "ops-1",
        _now(),
    )
    await repo.save(tenant_id, milestone)

    milestone.start(tenant_id, _now())
    await repo.save(tenant_id, milestone)

    fetched = await repo.find_by_incident(tenant_id, incident_id)
    assert len(fetched) == 1
    assert fetched[0].started_at is not None


@pytest.mark.asyncio
async def test_communication_log_append_only(session_factory) -> None:
    repo = PgIncidentCommunicationLogRepository(session_factory)
    tenant_id = TenantId(uuid7())
    incident_id = IncidentId(uuid7())

    entry = IncidentCommunicationLogEntry(
        entry_id=CommunicationLogEntryId.generate(),
        tenant_id=tenant_id,
        incident_id=incident_id,
        content="Notified stakeholders of containment",
        author="commander-1",
        recipient_summary="exec-team",
        communication_type=CommunicationType.STAKEHOLDER_UPDATE,
        logged_at=_now(),
        entry_sequence=1,
        prev_hash="0" * 64,
        entry_hash=IncidentCommunicationLogEntry.compute_hash(
            prev_hash="0" * 64,
            content="Notified stakeholders of containment",
            author="commander-1",
            logged_at=_now(),
            entry_sequence=1,
        ),
    )
    await repo.append(tenant_id, incident_id, entry)

    entries = await repo.find_by_incident(tenant_id, incident_id)
    assert len(entries) == 1
    assert entries[0].content == entry.content
