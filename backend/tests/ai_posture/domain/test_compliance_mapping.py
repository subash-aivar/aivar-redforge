"""Domain tests for AIComplianceMapping — Phase 5."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from ai_posture.domain.exceptions.domain_exceptions import (
    AttestationRequiredCannotAutoSatisfy,
)
from ai_posture.domain.services.ai_compliance_mapping_service import (
    AIComplianceMappingService,
)
from ai_posture.domain.value_objects.compliance_vos import (
    AIComplianceFrameworkRef,
    ApplicableControl,
    ControlEvidenceSnapshot,
    HumanAttestation,
)
from ai_posture.domain.value_objects.enums import (
    ComplianceControlStatus,
    ComplianceFrameworkId,
    EvaluationMode,
)
from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId


@pytest.fixture
def tenant() -> TenantId:
    return TenantId.generate()


@pytest.fixture
def asset() -> AISystemAssetId:
    return AISystemAssetId(uuid4())


def test_attestation_control_never_auto_satisfied(tenant: TenantId, asset: AISystemAssetId) -> None:
    svc = AIComplianceMappingService()
    control = ApplicableControl(
        AIComplianceFrameworkRef(
            ComplianceFrameworkId.EU_AI_ACT,
            "Art9_RiskManagement",
            "Risk Management",
        ),
        requires_human_attestation=True,
    )
    evidence = ControlEvidenceSnapshot(
        has_threat_profile=True,
        threat_max_exposure="Low",
        provenance_integrity_status="Verified",
        has_active_envelope=True,
    )
    mapping = svc.evaluate_control(tenant, asset, control, evidence, now=datetime.now(UTC))
    assert mapping.control_status == ComplianceControlStatus.PENDING_EVIDENCE
    assert mapping.evaluation_mode == EvaluationMode.PENDING_ATTESTATION
    assert mapping.control_status.value != ComplianceControlStatus.SATISFIED.value


def test_human_attestation_satisfies(tenant: TenantId, asset: AISystemAssetId) -> None:
    svc = AIComplianceMappingService()
    control = ApplicableControl(
        AIComplianceFrameworkRef(
            ComplianceFrameworkId.EU_AI_ACT,
            "Art9_RiskManagement",
            "Risk Management",
        ),
        requires_human_attestation=True,
    )
    evidence = ControlEvidenceSnapshot(False, None, None, False)
    now = datetime.now(UTC)
    mapping = svc.evaluate_control(
        tenant,
        asset,
        control,
        evidence,
        now=now,
        attestation=HumanAttestation("auditor-1", now, "reviewed"),
    )
    assert mapping.control_status == ComplianceControlStatus.SATISFIED
    assert mapping.evaluation_mode == EvaluationMode.HUMAN_ATTESTED


def test_gap_event_on_missing_threat_profile(tenant: TenantId, asset: AISystemAssetId) -> None:
    svc = AIComplianceMappingService()
    control = ApplicableControl(
        AIComplianceFrameworkRef(ComplianceFrameworkId.NIST_AI_RMF, "MAP_Threat", "Threat Mapping"),
        requires_human_attestation=False,
    )
    mapping = svc.evaluate_control(
        tenant,
        asset,
        control,
        ControlEvidenceSnapshot(False, None, None, False),
        now=datetime.now(UTC),
    )
    assert mapping.control_status == ComplianceControlStatus.GAP
    events = mapping.pop_events()
    types = {type(e).__name__ for e in events}
    assert "AIComplianceGapIdentified" in types


def test_cannot_record_satisfied_without_attestation(
    tenant: TenantId, asset: AISystemAssetId
) -> None:
    from ai_posture.domain.aggregates.ai_compliance_mapping import AIComplianceMapping
    from ai_posture.domain.value_objects.identifiers import AIComplianceMappingId

    with pytest.raises(AttestationRequiredCannotAutoSatisfy):
        AIComplianceMapping.record(
            AIComplianceMappingId.generate(),
            tenant,
            asset,
            AIComplianceFrameworkRef(ComplianceFrameworkId.EU_AI_ACT, "Art9_RiskManagement", "x"),
            ComplianceControlStatus.SATISFIED,
            requires_human_attestation=True,
            evaluation_mode=EvaluationMode.AUTO_EVALUATED,
            attestation=None,
            now=datetime.now(UTC),
        )
