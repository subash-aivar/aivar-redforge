"""IComplianceQueryPort — ACL to M24 (or local classification fallback)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ai_posture.domain.value_objects.compliance_vos import ApplicableControl
    from ai_posture.domain.value_objects.enums import (
        AISystemKind,
        ComplianceFrameworkId,
        DataSensitivityClassification,
    )
    from ai_posture.domain.value_objects.identifiers import TenantId


class IComplianceQueryPort(ABC):
    @abstractmethod
    async def resolve_applicable_controls(
        self,
        framework_id: ComplianceFrameworkId,
        ai_system_kind: AISystemKind,
        data_sensitivity: DataSensitivityClassification,
        tenant_id: TenantId,
    ) -> list[ApplicableControl]: ...
