"""Integration tests for InfrastructureEvidenceValidationAdapter
(M51.1 Phase 4.5) — real Postgres-backed `SecurityCondition`/
`InvestigationCase` rows, no seeded allow-list. Proves the real
cross-context evidence-existence path end to end."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from ulid import ULID

from redforge.application.evidence_existence.sqlalchemy_evidence_entity_existence_service import (
    SqlAlchemyEvidenceEntityExistenceService,
)
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.ingestion import SecurityConditionInput
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.infrastructure.database.repositories.investigations.case_repository import (
    SqlAlchemyInvestigationRepository,
)
from redforge.shared.identifiers import EntityId
from threat_actor_intel.domain.value_objects.identifiers import TenantId
from threat_actor_intel.infrastructure.acl.infrastructure_evidence_validation_adapter import (
    InfrastructureEvidenceValidationAdapter,
)

pytestmark = pytest.mark.integration


async def _make_security_condition(session_factory, organization_id: str) -> str:
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=organization_id,
        asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST,
        raw_external_id=f"{EntityId.generate()}:{EntityId.generate()}",
        name="test-host",
        description="",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    condition_service = TenantSecurityConditionService(session_factory)
    condition = await condition_service.ingest(
        SecurityConditionInput(
            organization_id=organization_id,
            affected_asset_id=asset.id,
            source_category="network_discovery",
            stable_rule_id="SENSITIVE_SERVICE_OBSERVED",
            evidence_state="observed",
            severity="medium",
            title="Sensitive service observed",
            summary="SSH observed on host.",
        )
    )
    return condition.id


async def _make_investigation_case(session, organization_id: str) -> str:
    repo = SqlAlchemyInvestigationRepository(session)
    now = datetime.now(UTC)
    model, _created = await repo.create_or_get_active(
        organization_id=organization_id,
        correlation_key=str(ULID()),
        title="Cross-domain correlation",
        summary="Test case",
        status="OPEN",
        severity="MEDIUM",
        confidence="MEDIUM",
        source_domains=["network_security"],
        involved_entities=[{"type": "ip", "id": "10.0.0.1"}],
        first_observed_at=now,
        opened_at=now,
        now=now,
    )
    await session.commit()
    return model.id


@pytest.mark.asyncio
async def test_real_same_tenant_security_condition_citation_validates(
    tai_session_factory, tai_session
) -> None:
    organization_id = str(EntityId.generate())
    condition_id = await _make_security_condition(tai_session_factory, organization_id)
    adapter = InfrastructureEvidenceValidationAdapter(
        SqlAlchemyEvidenceEntityExistenceService(tai_session)
    )
    result = await adapter.validate(
        TenantId.from_string(organization_id), "SecurityCondition", condition_id, "real citation"
    )
    assert result is True


@pytest.mark.asyncio
async def test_real_same_tenant_investigation_citation_validates(
    tai_session_factory, tai_session
) -> None:
    organization_id = str(EntityId.generate())
    case_id = await _make_investigation_case(tai_session, organization_id)
    adapter = InfrastructureEvidenceValidationAdapter(
        SqlAlchemyEvidenceEntityExistenceService(tai_session)
    )
    result = await adapter.validate(
        TenantId.from_string(organization_id), "InvestigationCase", case_id, "real citation"
    )
    assert result is True


@pytest.mark.asyncio
async def test_missing_entity_is_rejected(tai_session) -> None:
    adapter = InfrastructureEvidenceValidationAdapter(
        SqlAlchemyEvidenceEntityExistenceService(tai_session)
    )
    result = await adapter.validate(
        TenantId.generate(), "SecurityCondition", str(ULID()), "fabricated citation"
    )
    assert result is False


@pytest.mark.asyncio
async def test_cross_tenant_reference_is_rejected_as_not_found(
    tai_session_factory, tai_session
) -> None:
    owner_org = str(EntityId.generate())
    other_org = str(EntityId.generate())
    condition_id = await _make_security_condition(tai_session_factory, owner_org)
    adapter = InfrastructureEvidenceValidationAdapter(
        SqlAlchemyEvidenceEntityExistenceService(tai_session)
    )
    result = await adapter.validate(
        TenantId.from_string(other_org), "SecurityCondition", condition_id, "cross-tenant claim"
    )
    assert result is False


@pytest.mark.asyncio
async def test_unsupported_entity_type_is_rejected(tai_session_factory, tai_session) -> None:
    organization_id = str(EntityId.generate())
    condition_id = await _make_security_condition(tai_session_factory, organization_id)
    adapter = InfrastructureEvidenceValidationAdapter(
        SqlAlchemyEvidenceEntityExistenceService(tai_session)
    )
    result = await adapter.validate(
        TenantId.from_string(organization_id),
        "SomeUnsupportedType",
        condition_id,
        "citation",
    )
    assert result is False
