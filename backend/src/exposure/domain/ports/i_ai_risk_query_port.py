"""ACL port → M31 AI risk (Phase 2). AISystemRisk is an amplifier, not a SignalDomain."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from exposure.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class AIRiskFacts:
    asset_ref_id: str
    exposure_level: float
    amplifier_weight: Decimal
    profile_ref: str


class IAIRiskQueryPort(ABC):
    @abstractmethod
    async def get_risk_for_asset(
        self, tenant_id: TenantId, asset_ref_id: str
    ) -> AIRiskFacts | None: ...
