"""Seedable ACL adapters for M27/M26/M28/M31 — intentional until live wiring."""

from __future__ import annotations

from decimal import Decimal

from exposure.domain.ports.i_ai_risk_query_port import AIRiskFacts, IAIRiskQueryPort
from exposure.domain.ports.i_cloud_exposure_query_port import (
    CloudMisconfigFacts,
    ICloudExposureQueryPort,
)
from exposure.domain.ports.i_detection_coverage_query_port import (
    DetectionGapFacts,
    IDetectionCoverageQueryPort,
)
from exposure.domain.ports.i_vulnerability_query_port import (
    IVulnerabilityQueryPort,
    VulnerabilitySignalFacts,
)
from exposure.domain.value_objects.identifiers import TenantId


class StubVulnerabilityQueryAdapter(IVulnerabilityQueryPort):
    def __init__(self) -> None:
        self.instances: dict[tuple[str, str], VulnerabilitySignalFacts] = {}

    def seed(self, tenant_id: TenantId, facts: VulnerabilitySignalFacts) -> None:
        self.instances[(str(tenant_id), facts.vulnerability_instance_id)] = facts

    async def get_instance(
        self, tenant_id: TenantId, vulnerability_instance_id: str
    ) -> VulnerabilitySignalFacts | None:
        return self.instances.get((str(tenant_id), vulnerability_instance_id))


class StubCloudExposureQueryAdapter(ICloudExposureQueryPort):
    def __init__(self) -> None:
        self.items: dict[tuple[str, str], CloudMisconfigFacts] = {}

    def seed(self, tenant_id: TenantId, facts: CloudMisconfigFacts) -> None:
        self.items[(str(tenant_id), facts.misconfiguration_id)] = facts

    async def get_misconfiguration(
        self, tenant_id: TenantId, misconfiguration_id: str
    ) -> CloudMisconfigFacts | None:
        return self.items.get((str(tenant_id), misconfiguration_id))


class StubDetectionCoverageQueryAdapter(IDetectionCoverageQueryPort):
    def __init__(self) -> None:
        self.gaps: dict[tuple[str, str], DetectionGapFacts] = {}

    def seed(self, tenant_id: TenantId, facts: DetectionGapFacts) -> None:
        self.gaps[(str(tenant_id), facts.gap_id)] = facts

    async def get_gap(self, tenant_id: TenantId, gap_id: str) -> DetectionGapFacts | None:
        return self.gaps.get((str(tenant_id), gap_id))


class StubAIRiskQueryAdapter(IAIRiskQueryPort):
    def __init__(self) -> None:
        self.risks: dict[tuple[str, str], AIRiskFacts] = {}

    def seed(self, tenant_id: TenantId, facts: AIRiskFacts) -> None:
        self.risks[(str(tenant_id), facts.asset_ref_id)] = facts

    async def get_risk_for_asset(
        self, tenant_id: TenantId, asset_ref_id: str
    ) -> AIRiskFacts | None:
        return self.risks.get((str(tenant_id), asset_ref_id))


def ai_weight_from_score(ai_risk_score: float, max_multiplier: float = 1.0) -> Decimal:
    """Review-suggested parameterization: 1.0 + (score/100)*max → store as additive weight."""
    factor = 1.0 + (ai_risk_score / 100.0) * max_multiplier
    return Decimal(str(max(0.0, factor - 1.0)))
