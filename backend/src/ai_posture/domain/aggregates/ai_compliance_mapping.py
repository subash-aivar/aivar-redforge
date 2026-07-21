"""AIComplianceMapping aggregate root — Phase 5."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_posture.domain.events.posture_events import (
    AIComplianceGapIdentified,
    AIComplianceMappingRecorded,
)
from ai_posture.domain.exceptions.domain_exceptions import (
    AttestationRequiredCannotAutoSatisfy,
    TenantMismatch,
)
from ai_posture.domain.value_objects.enums import (
    ComplianceControlStatus,
    EvaluationMode,
)

if TYPE_CHECKING:
    from datetime import datetime

    from ai_posture.domain.events.base import BaseDomainEvent
    from ai_posture.domain.value_objects.compliance_vos import (
        AIComplianceFrameworkRef,
        HumanAttestation,
    )
    from ai_posture.domain.value_objects.identifiers import (
        AIComplianceMappingId,
        AISystemAssetId,
        TenantId,
    )


class AIComplianceMapping:
    __slots__ = (
        "_pending_events",
        "_version",
        "ai_system_asset_id",
        "attestation",
        "control_status",
        "evaluation_mode",
        "framework_ref",
        "mapping_id",
        "recorded_at",
        "requires_human_attestation",
        "tenant_id",
    )

    def __init__(
        self,
        mapping_id: AIComplianceMappingId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        framework_ref: AIComplianceFrameworkRef,
        control_status: ComplianceControlStatus,
        requires_human_attestation: bool,
        evaluation_mode: EvaluationMode,
        attestation: HumanAttestation | None,
        recorded_at: datetime,
        version: int = 1,
    ) -> None:
        self.mapping_id = mapping_id
        self.tenant_id = tenant_id
        self.ai_system_asset_id = ai_system_asset_id
        self.framework_ref = framework_ref
        self.control_status = control_status
        self.requires_human_attestation = requires_human_attestation
        self.evaluation_mode = evaluation_mode
        self.attestation = attestation
        self.recorded_at = recorded_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    @classmethod
    def record(
        cls,
        mapping_id: AIComplianceMappingId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        framework_ref: AIComplianceFrameworkRef,
        control_status: ComplianceControlStatus,
        *,
        requires_human_attestation: bool,
        evaluation_mode: EvaluationMode,
        attestation: HumanAttestation | None,
        now: datetime,
    ) -> AIComplianceMapping:
        if (
            requires_human_attestation
            and control_status == ComplianceControlStatus.SATISFIED
            and (evaluation_mode != EvaluationMode.HUMAN_ATTESTED or attestation is None)
        ):
            raise AttestationRequiredCannotAutoSatisfy(framework_ref.control_id)
        m = cls(
            mapping_id=mapping_id,
            tenant_id=tenant_id,
            ai_system_asset_id=ai_system_asset_id,
            framework_ref=framework_ref,
            control_status=control_status,
            requires_human_attestation=requires_human_attestation,
            evaluation_mode=evaluation_mode,
            attestation=attestation,
            recorded_at=now,
            version=1,
        )
        m._pending_events.append(
            AIComplianceMappingRecorded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(mapping_id),
                aggregate_type="AIComplianceMapping",
                ai_system_asset_id=str(ai_system_asset_id),
                framework_id=framework_ref.framework_id.value,
                control_id=framework_ref.control_id,
                control_status=control_status.value,
                requires_human_attestation=requires_human_attestation,
                evaluation_mode=evaluation_mode.value,
            )
        )
        if control_status == ComplianceControlStatus.GAP:
            m._pending_events.append(
                AIComplianceGapIdentified(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(mapping_id),
                    aggregate_type="AIComplianceMapping",
                    ai_system_asset_id=str(ai_system_asset_id),
                    framework_id=framework_ref.framework_id.value,
                    control_id=framework_ref.control_id,
                )
            )
        return m

    def apply_human_attestation(
        self,
        tenant_id: TenantId,
        attestation: HumanAttestation,
        *,
        satisfied: bool,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not self.requires_human_attestation:
            raise AttestationRequiredCannotAutoSatisfy(
                f"{self.framework_ref.control_id}: not attestation-required"
            )
        self.attestation = attestation
        self.evaluation_mode = EvaluationMode.HUMAN_ATTESTED
        self.control_status = (
            ComplianceControlStatus.SATISFIED if satisfied else ComplianceControlStatus.GAP
        )
        self.recorded_at = now
        self._version += 1
        self._pending_events.append(
            AIComplianceMappingRecorded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.mapping_id),
                aggregate_type="AIComplianceMapping",
                ai_system_asset_id=str(self.ai_system_asset_id),
                framework_id=self.framework_ref.framework_id.value,
                control_id=self.framework_ref.control_id,
                control_status=self.control_status.value,
                requires_human_attestation=True,
                evaluation_mode=EvaluationMode.HUMAN_ATTESTED.value,
            )
        )
