"""Correlate dimension contributions into CloudRiskFactor records."""

from __future__ import annotations

from redforge.domain.cloud_security.risk.engine import CloudRiskEngine, RiskSignalSnapshot
from redforge.domain.cloud_security.risk.entities import RiskContribution, RiskEvidence
from redforge.domain.cloud_security.risk.factor import CloudRiskFactor
from redforge.domain.cloud_security.risk.value_objects import (
    RiskCategory,
    RiskConfidence,
    RiskDimensionScores,
    RiskSource,
    RiskWeightProfile,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId


class RiskCorrelationService:
    """Turn engine contributions into persisted CloudRiskFactor aggregates."""

    def __init__(self, engine: CloudRiskEngine | None = None) -> None:
        self._engine = engine or CloudRiskEngine()

    def correlate(
        self,
        *,
        organization_id: OrganizationId,
        cloud_asset_id: CloudAssetId,
        snapshot: RiskSignalSnapshot,
        weights: RiskWeightProfile | None = None,
    ) -> tuple[
        RiskDimensionScores,
        list[RiskContribution],
        list[RiskEvidence],
        list[CloudRiskFactor],
    ]:
        dimensions, components, evidence = self._engine.score_dimensions(
            snapshot, weights=weights
        )
        factors: list[CloudRiskFactor] = []
        for component in components:
            if component.raw_score <= 0.0 and component.dimension != "attack_path":
                continue
            factors.append(
                CloudRiskFactor.create(
                    organization_id=organization_id,
                    cloud_asset_id=cloud_asset_id,
                    category=component.category,
                    source=self._source_for(component.dimension),
                    title=f"{component.dimension}:{component.raw_score:.2f}",
                    description=component.rationale,
                    score=component.raw_score,
                    confidence=RiskConfidence.MEDIUM,
                    evidence=list(evidence),
                    metadata={
                        "weight": component.weight,
                        "weighted_score": component.weighted_score,
                        "dimension": component.dimension,
                    },
                )
            )
        return dimensions, components, evidence, factors

    @staticmethod
    def _source_for(dimension: str) -> RiskSource:
        mapping = {
            "cspm": RiskSource.CSPM,
            "identity": RiskSource.IDENTITY,
            "kubernetes": RiskSource.KUBERNETES,
            "runtime": RiskSource.RUNTIME,
            "compliance": RiskSource.COMPLIANCE,
            "threat_intel": RiskSource.THREAT_INTEL,
            "exposure": RiskSource.EXPOSURE,
            "criticality": RiskSource.INVENTORY,
            "attack_path": RiskSource.COMPOSITE,
        }
        return mapping.get(dimension, RiskSource.COMPOSITE)

    @staticmethod
    def category_for_dimension(dimension: str) -> RiskCategory:
        return CloudRiskEngine._category_for(dimension)
