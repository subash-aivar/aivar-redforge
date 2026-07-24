"""Phase 5 compliance + report application flows."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ai_posture.application.commands.posture_commands import (
    ApproveAISystemAssetRegistrationCommand,
    AssignAssetOwnerCommand,
    ClassifyAISystemAssetCommand,
    ComputeRiskScoreCommand,
    CreateThreatProfileCommand,
    EvaluateComplianceMappingCommand,
    RecordComplianceAttestationCommand,
    RegisterAISystemAssetCommand,
)
from ai_posture.application.queries.report_queries import (
    GetCompliancePostureQuery,
    GetInventoryDashboardQuery,
    GetRiskRegisterQuery,
    GetShadowAIDiscoveryReportQuery,
    GetSupplyChainIntegrityQuery,
)
from ai_posture.domain.value_objects.identifiers import TenantId
from ai_posture.infrastructure.acl.degraded_adapters import StubInventoryQueryAdapter
from ai_posture.infrastructure.acl.phase5_adapters import (
    StubDiscoveryScanFactsAdapter,
    StubProvenanceIntegrityAdapter,
)
from ai_posture.infrastructure.container import AIPostureContainer
from ai_posture.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)
from tests.ai_posture.conftest import ADMIN, ANALYST, APPROVER, ENGINEER, READER


@pytest.fixture
def provenance() -> StubProvenanceIntegrityAdapter:
    return StubProvenanceIntegrityAdapter()


@pytest.fixture
def discovery() -> StubDiscoveryScanFactsAdapter:
    return StubDiscoveryScanFactsAdapter()


@pytest.fixture
def phase5_container(
    uow: InMemoryUnitOfWork,
    inventory: StubInventoryQueryAdapter,
    provenance: StubProvenanceIntegrityAdapter,
    discovery: StubDiscoveryScanFactsAdapter,
) -> AIPostureContainer:
    return AIPostureContainer(
        uow_factory=lambda: uow,
        inventory_port=inventory,
        provenance_port=provenance,
        discovery_port=discovery,
    )


async def _onboard(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
    *,
    kind: str = "FoundationModelAPI",
) -> UUID:
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant_id.value)
    dto = await container.asset_service.register(
        RegisterAISystemAssetCommand(
            tenant_id=tenant_id,
            asset_ref_id=asset_ref,
            discovery_source="ManualRegistration",
            actor_roles=ENGINEER,
        )
    )
    asset_id = UUID(dto.asset_id)
    await container.asset_service.classify(
        ClassifyAISystemAssetCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            ai_system_kind=kind,
            actor_roles=ENGINEER,
        )
    )
    await container.asset_service.assign_owner(
        AssignAssetOwnerCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            owner_id="owner-1",
            actor_roles=ENGINEER,
        )
    )
    await container.asset_service.approve_registration(
        ApproveAISystemAssetRegistrationCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            actor_roles=APPROVER,
        )
    )
    return asset_id


@pytest.mark.asyncio
async def test_evaluate_eu_and_nist_frameworks(
    phase5_container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _onboard(phase5_container, inventory, tenant_id)
    await phase5_container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    eu = await phase5_container.compliance_service.evaluate(
        EvaluateComplianceMappingCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            framework_id="EU_AI_Act",
            actor_roles=ENGINEER,
        )
    )
    nist = await phase5_container.compliance_service.evaluate(
        EvaluateComplianceMappingCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            framework_id="NIST_AI_RMF",
            actor_roles=ENGINEER,
        )
    )
    assert len(eu) >= 2
    assert len(nist) >= 2
    attest_pending = [m for m in eu if m.requires_human_attestation]
    assert attest_pending
    assert all(m.control_status != "Satisfied" for m in attest_pending)


@pytest.mark.asyncio
async def test_attestation_end_to_end(
    phase5_container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _onboard(phase5_container, inventory, tenant_id)
    await phase5_container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    mappings = await phase5_container.compliance_service.evaluate(
        EvaluateComplianceMappingCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            framework_id="EU_AI_Act",
            actor_roles=ENGINEER,
        )
    )
    pending = next(m for m in mappings if m.requires_human_attestation)
    attested = await phase5_container.compliance_service.record_attestation(
        RecordComplianceAttestationCommand(
            tenant_id=tenant_id,
            mapping_id=UUID(pending.mapping_id),
            attestor_id="ciso-1",
            satisfied=True,
            notes="process reviewed",
            actor_roles=ANALYST,
        )
    )
    assert attested.control_status == "Satisfied"
    assert attested.evaluation_mode == "HumanAttested"
    assert attested.attestor_id == "ciso-1"


@pytest.mark.asyncio
async def test_ciso_flow_inventory_and_reports(
    phase5_container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    provenance: StubProvenanceIntegrityAdapter,
    discovery: StubDiscoveryScanFactsAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _onboard(phase5_container, inventory, tenant_id)
    await phase5_container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    await phase5_container.risk_service.compute(
        ComputeRiskScoreCommand(tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER)
    )
    await phase5_container.compliance_service.evaluate(
        EvaluateComplianceMappingCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            framework_id="EU_AI_Act",
            actor_roles=ENGINEER,
        )
    )
    provenance.seed(
        tenant_id.value,
        asset_id,
        "Verified",
        verification_method="ProviderAttestation",
        trust_delegation_note="provider note",
    )
    discovery.seed(
        tenant_id.value,
        sources=["CloudProviderScan", "KubernetesAdmission"],
        partial=True,
        failed_partitions=["CloudProviderScan:bad"],
    )
    rebuilt = await phase5_container.rebuild_service.rebuild_tenant(tenant_id.value, ADMIN)
    assert rebuilt["store"]["inventory"] >= 1

    inventory_view = await phase5_container.report_queries.inventory(
        GetInventoryDashboardQuery(tenant_id=tenant_id, actor_roles=READER)
    )
    assert inventory_view["coverage_scope"]
    assert "CloudProviderScan" in inventory_view["configured_discovery_sources"]

    risk = await phase5_container.report_queries.risk_register(
        GetRiskRegisterQuery(tenant_id=tenant_id, actor_roles=READER)
    )
    assert risk["entries"]
    assert "score_input_version" in risk["entries"][0]
    assert "is_stale" in risk["entries"][0]

    shadow = await phase5_container.report_queries.shadow_discovery(
        GetShadowAIDiscoveryReportQuery(tenant_id=tenant_id, actor_roles=READER)
    )
    assert "scope_of_report" in shadow
    assert shadow["partial_scans"]

    compliance = await phase5_container.report_queries.compliance_posture(
        GetCompliancePostureQuery(
            tenant_id=tenant_id,
            framework_id="EU_AI_Act",
            actor_roles=READER,
        )
    )
    assert compliance["controls"]

    supply = await phase5_container.report_queries.supply_chain(
        GetSupplyChainIntegrityQuery(tenant_id=tenant_id, actor_roles=READER)
    )
    assert supply["models"][0]["tier_label"] == "Provider-Attested"


@pytest.mark.asyncio
async def test_risk_score_uses_provenance_component(
    phase5_container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    provenance: StubProvenanceIntegrityAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _onboard(phase5_container, inventory, tenant_id)
    provenance.seed(tenant_id.value, asset_id, "Mismatched")
    snap = await phase5_container.risk_service.compute(
        ComputeRiskScoreCommand(tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER)
    )
    assert snap.components["provenance_integrity_component"] == 90.0
