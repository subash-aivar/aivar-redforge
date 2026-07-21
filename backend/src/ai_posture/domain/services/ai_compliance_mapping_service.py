"""AIComplianceMappingService — evaluate controls from evidence; never auto-satisfy attestation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_posture.domain.aggregates.ai_compliance_mapping import AIComplianceMapping
from ai_posture.domain.value_objects.enums import (
    ComplianceControlStatus,
    EvaluationMode,
)
from ai_posture.domain.value_objects.identifiers import AIComplianceMappingId

if TYPE_CHECKING:
    from datetime import datetime

    from ai_posture.domain.value_objects.compliance_vos import (
        ApplicableControl,
        ControlEvidenceSnapshot,
        HumanAttestation,
    )
    from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId


class AIComplianceMappingService:
    def evaluate_control(
        self,
        tenant_id: TenantId,
        asset_id: AISystemAssetId,
        control: ApplicableControl,
        evidence: ControlEvidenceSnapshot,
        *,
        now: datetime,
        attestation: HumanAttestation | None = None,
    ) -> AIComplianceMapping:
        if control.requires_human_attestation:
            if attestation is not None:
                return AIComplianceMapping.record(
                    AIComplianceMappingId.generate(),
                    tenant_id,
                    asset_id,
                    control.framework_ref,
                    ComplianceControlStatus.SATISFIED,
                    requires_human_attestation=True,
                    evaluation_mode=EvaluationMode.HUMAN_ATTESTED,
                    attestation=attestation,
                    now=now,
                )
            return AIComplianceMapping.record(
                AIComplianceMappingId.generate(),
                tenant_id,
                asset_id,
                control.framework_ref,
                ComplianceControlStatus.PENDING_EVIDENCE,
                requires_human_attestation=True,
                evaluation_mode=EvaluationMode.PENDING_ATTESTATION,
                attestation=None,
                now=now,
            )

        status = self._auto_status(control, evidence)
        return AIComplianceMapping.record(
            AIComplianceMappingId.generate(),
            tenant_id,
            asset_id,
            control.framework_ref,
            status,
            requires_human_attestation=False,
            evaluation_mode=EvaluationMode.AUTO_EVALUATED,
            attestation=None,
            now=now,
        )

    def _auto_status(
        self, control: ApplicableControl, evidence: ControlEvidenceSnapshot
    ) -> ComplianceControlStatus:
        cid = control.framework_ref.control_id.lower()
        if "threat" in cid or "risk" in cid:
            if not evidence.has_threat_profile:
                return ComplianceControlStatus.GAP
            if evidence.threat_max_exposure in {"Critical", "High"}:
                return ComplianceControlStatus.PARTIALLY_SATISFIED
            return ComplianceControlStatus.SATISFIED
        if "provenance" in cid or "supply" in cid:
            if evidence.provenance_integrity_status is None:
                return ComplianceControlStatus.GAP
            if evidence.provenance_integrity_status == "Verified":
                return ComplianceControlStatus.SATISFIED
            if evidence.provenance_integrity_status in {"Unverified", "VerificationFailed"}:
                return ComplianceControlStatus.PARTIALLY_SATISFIED
            return ComplianceControlStatus.GAP
        if "agent" in cid or "envelope" in cid or "governance" in cid:
            if evidence.has_active_envelope:
                return ComplianceControlStatus.SATISFIED
            return ComplianceControlStatus.GAP
        # Generic machine-evaluable control: presence of threat profile is baseline
        if evidence.has_threat_profile:
            return ComplianceControlStatus.SATISFIED
        return ComplianceControlStatus.PENDING_EVIDENCE
