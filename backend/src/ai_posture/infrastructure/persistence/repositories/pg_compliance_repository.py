"""PostgreSQL AIComplianceMapping repository."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import select

from ai_posture.domain.aggregates.ai_compliance_mapping import AIComplianceMapping
from ai_posture.domain.repositories.i_ai_compliance_mapping_repository import (
    IAIComplianceMappingRepository,
)
from ai_posture.domain.value_objects.compliance_vos import (
    AIComplianceFrameworkRef,
    HumanAttestation,
)
from ai_posture.domain.value_objects.enums import (
    ComplianceControlStatus,
    ComplianceFrameworkId,
    EvaluationMode,
)
from ai_posture.domain.value_objects.identifiers import (
    AIComplianceMappingId,
    AISystemAssetId,
    TenantId,
)
from ai_posture.infrastructure.persistence.models.ai_posture_models import (
    AIComplianceMappingModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgComplianceMappingRepository(IAIComplianceMappingRepository):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, mapping: AIComplianceMapping) -> None:
        row = await self._session.get(AIComplianceMappingModel, mapping.mapping_id.value)
        payload = {
            "id": mapping.mapping_id.value,
            "tenant_id": mapping.tenant_id.value,
            "ai_system_asset_id": mapping.ai_system_asset_id.value,
            "framework_id": mapping.framework_ref.framework_id.value,
            "control_id": mapping.framework_ref.control_id,
            "control_title": mapping.framework_ref.control_title,
            "control_status": mapping.control_status.value,
            "requires_human_attestation": mapping.requires_human_attestation,
            "evaluation_mode": mapping.evaluation_mode.value,
            "attestor_id": mapping.attestation.attestor_id if mapping.attestation else None,
            "attested_at": mapping.attestation.attested_at if mapping.attestation else None,
            "attestation_notes": mapping.attestation.notes if mapping.attestation else "",
            "recorded_at": mapping.recorded_at,
            "row_version": mapping.version,
        }
        if row is None:
            self._session.add(AIComplianceMappingModel(**payload))
            return
        for key, value in payload.items():
            if key != "id":
                setattr(row, key, value)

    async def find_by_id(
        self, mapping_id: AIComplianceMappingId, tenant_id: TenantId
    ) -> AIComplianceMapping | None:
        row = await self._session.get(AIComplianceMappingModel, mapping_id.value)
        if row is None or row.tenant_id != tenant_id.value:
            return None
        return self._from_row(row)

    async def find_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> list[AIComplianceMapping]:
        result = await self._session.execute(
            select(AIComplianceMappingModel).where(
                AIComplianceMappingModel.tenant_id == tenant_id.value,
                AIComplianceMappingModel.ai_system_asset_id == asset_id.value,
            )
        )
        return [self._from_row(r) for r in result.scalars()]

    async def find_gaps_by_framework(
        self, framework_id: ComplianceFrameworkId, tenant_id: TenantId
    ) -> list[AIComplianceMapping]:
        result = await self._session.execute(
            select(AIComplianceMappingModel).where(
                AIComplianceMappingModel.tenant_id == tenant_id.value,
                AIComplianceMappingModel.framework_id == framework_id.value,
                AIComplianceMappingModel.control_status == ComplianceControlStatus.GAP.value,
            )
        )
        return [self._from_row(r) for r in result.scalars()]

    async def count_gaps_for_asset(self, asset_id: AISystemAssetId, tenant_id: TenantId) -> int:
        items = await self.find_by_asset(asset_id, tenant_id)
        return sum(1 for m in items if m.control_status == ComplianceControlStatus.GAP)

    def _from_row(self, row: AIComplianceMappingModel) -> AIComplianceMapping:
        attestation = None
        if row.attestor_id and row.attested_at:
            attestation = HumanAttestation(
                row.attestor_id, row.attested_at, row.attestation_notes or ""
            )
        return AIComplianceMapping(
            mapping_id=AIComplianceMappingId(row.id),
            tenant_id=TenantId(row.tenant_id),
            ai_system_asset_id=AISystemAssetId(row.ai_system_asset_id),
            framework_ref=AIComplianceFrameworkRef(
                ComplianceFrameworkId(row.framework_id),
                row.control_id,
                row.control_title,
            ),
            control_status=ComplianceControlStatus(row.control_status),
            requires_human_attestation=row.requires_human_attestation,
            evaluation_mode=EvaluationMode(row.evaluation_mode),
            attestation=attestation,
            recorded_at=row.recorded_at,
            version=row.row_version,
        )
