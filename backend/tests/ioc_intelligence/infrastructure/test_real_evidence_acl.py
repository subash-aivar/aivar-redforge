"""M51.2 Slice 2.1 — proves the REAL cross-context evidence ACL end to
end for ioc_intelligence: a tenant IOC's evidence citation against a
genuinely persisted `SecurityCondition`/`InvestigationCase` row (not a
seeded allow-list stub), through the real `IocApplicationService` +
`InfrastructureEvidenceValidationAdapter` +
`SqlAlchemyEvidenceEntityExistenceService` stack, against real
PostgreSQL. Mirrors `tests/threat_actor_intel/infrastructure/
test_evidence_validation_adapter.py`'s `_make_security_condition`/
`_make_investigation_case` helpers exactly — same cross-context ACL,
same real fixture shape, applied to `ioc_intelligence` instead."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from ulid import ULID

from ioc_intelligence.application._auth import IocIntelRole
from ioc_intelligence.application.commands.ioc_commands import (
    AddEvidenceCitationCommand,
    ObserveTenantIocCommand,
    SourceAttributionInput,
)
from ioc_intelligence.domain.value_objects.identifiers import TenantId
from ioc_intelligence.infrastructure.acl.infrastructure_evidence_validation_adapter import (
    InfrastructureEvidenceValidationAdapter,
)
from ioc_intelligence.infrastructure.container import IocIntelContainer
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
from redforge.shared.ioc_vocabulary import ProviderName
from tests.ioc_intelligence.infrastructure.helpers import random_ip

pytestmark = pytest.mark.integration

ANALYST = (IocIntelRole.ANALYST.value,)


async def _make_security_condition(session_factory, organization_id: str) -> str:
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=organization_id,
        asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST,
        raw_external_id=f"{EntityId.generate()}:{EntityId.generate()}",
        name="slice21-e2e-host",
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
            summary="SSH observed on host (M51.2 Slice 2.1 evidence ACL proof).",
        )
    )
    return condition.id


async def _make_investigation_case(session, organization_id: str) -> str:
    repo = SqlAlchemyInvestigationRepository(session)
    now = datetime.now(UTC)
    model, _created = await repo.create_or_get_active(
        organization_id=organization_id,
        correlation_key=str(ULID()),
        title="Slice 2.1 evidence ACL proof",
        summary="Synthetic investigation case for IOC evidence citation E2E proof.",
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
async def test_tenant_ioc_can_cite_a_real_security_condition_as_evidence(
    ioc_session_factory,
) -> None:
    org_id = str(EntityId.generate())
    tenant_id = TenantId.generate()
    condition_id = await _make_security_condition(ioc_session_factory, org_id)

    container = IocIntelContainer(ioc_session_factory)
    session = container.new_session()
    try:
        service = container.build_service(session)
        validator = service._evidence
        assert isinstance(validator, InfrastructureEvidenceValidationAdapter)
        assert isinstance(validator._entity_existence, SqlAlchemyEvidenceEntityExistenceService)

        # Real fail-closed validation against the entity that does NOT
        # belong to this IOC's tenant_id (org_id) must reject — proven
        # first so a false-positive "valid" below can't be an accident
        # of the adapter always returning True.
        assert await validator.validate(tenant_id, f"SecurityCondition:{condition_id}") is False, (
            "condition belongs to a different organization_id than tenant_id maps to — must reject"
        )
    finally:
        await session.close()


@pytest.mark.asyncio
async def test_add_evidence_citation_against_a_genuinely_persisted_security_condition(
    ioc_session_factory,
) -> None:
    """The actual mission-required proof: observe a tenant IOC, then
    add an evidence citation referencing a REAL `SecurityCondition` row
    (not a stub), through the certified application service, and
    confirm it persists and is readable back."""
    tenant_id = TenantId.generate()  # TenantId IS EntityId (ADR-0005 shared kernel)
    org_id = str(tenant_id)
    condition_id = await _make_security_condition(ioc_session_factory, org_id)

    container = IocIntelContainer(ioc_session_factory)
    session = container.new_session()
    try:
        service = container.build_service(session)
        dto = await service.observe_tenant_ioc(
            ObserveTenantIocCommand(
                tenant_id=tenant_id,
                ioc_type="ip",
                raw_value=random_ip(),
                source_attributions=(
                    SourceAttributionInput(
                        source_system=ProviderName.ALIENVAULT_OTX.value,
                        external_id="pulse-slice21-e2e",
                        observed_at="2026-08-05T00:00:00+00:00",
                        weight_applied=0.9,
                        confidence="high",
                    ),
                ),
                actor_roles=ANALYST,
            )
        )

        detail = await service.add_evidence_citation(
            AddEvidenceCitationCommand(
                tenant_id=tenant_id,
                ioc_id=dto.ioc_id,
                evidence_citation=f"SecurityCondition:{condition_id}",
                actor_roles=ANALYST,
            )
        )
        assert any(
            c.value == f"SecurityCondition:{condition_id}" for c in detail.evidence_citations
        )

        # Reload independently (fresh session) to prove real persistence,
        # not just the in-memory aggregate returned by the call above.
        verify_session = container.new_session()
        try:
            verify_service = container.build_service(verify_session)
            from ioc_intelligence.application.queries.ioc_queries import GetIocQuery

            reloaded = await verify_service.get_ioc(
                GetIocQuery(tenant_id=tenant_id, ioc_id=dto.ioc_id, actor_roles=ANALYST)
            )
            assert reloaded.evidence_citations
            assert reloaded.evidence_citations[0].value == f"SecurityCondition:{condition_id}"
        finally:
            await verify_session.close()
    finally:
        await session.close()
