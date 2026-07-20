"""Deterministic CloudRiskEngine — pure scoring (no I/O)."""

from __future__ import annotations

from dataclasses import dataclass

from redforge.domain.cloud_security.risk.entities import RiskContribution, RiskEvidence
from redforge.domain.cloud_security.risk.value_objects import (
    RiskCategory,
    RiskDimensionScores,
    RiskSource,
    RiskWeightProfile,
    compute_weighted_overall,
    severity_to_score,
)


@dataclass(frozen=True, slots=True)
class RiskSignalSnapshot:
    """Provider-agnostic input snapshot collected from existing domains (read-only)."""

    open_finding_severities: tuple[str, ...] = ()
    privilege_level: str = "NONE"
    network_exposure: str = "UNKNOWN"
    encryption_at_rest: bool = True
    public_accessibility: bool = False
    compliance_gap_ratio: float = 0.0  # 0..1
    k8s_security_score: float | None = None  # 0..100 higher=better
    runtime_event_severities: tuple[str, ...] = ()
    business_criticality: str = "MEDIUM"
    threat_intel_score: float = 0.0
    lateral_movement_potential: str = "UNKNOWN"  # metadata only
    provider_type: str = "*"
    asset_type: str = ""
    tags: tuple[tuple[str, str], ...] = ()


class CloudRiskEngine:
    """Deterministic, versioned risk calculation — reproducible for same inputs."""

    def score_dimensions(
        self,
        snapshot: RiskSignalSnapshot,
        *,
        weights: RiskWeightProfile | None = None,
    ) -> tuple[RiskDimensionScores, list[RiskContribution], list[RiskEvidence]]:
        profile = weights or RiskWeightProfile.default()
        cspm = self._cspm_score(snapshot.open_finding_severities)
        identity = self._identity_score(snapshot.privilege_level)
        exposure = self._exposure_score(
            network_exposure=snapshot.network_exposure,
            public_accessibility=snapshot.public_accessibility,
            encryption_at_rest=snapshot.encryption_at_rest,
        )
        compliance = min(10.0, max(0.0, snapshot.compliance_gap_ratio * 10.0))
        kubernetes = self._k8s_score(snapshot.k8s_security_score)
        runtime = self._runtime_score(snapshot.runtime_event_severities)
        criticality = self._criticality_score(snapshot.business_criticality, snapshot.tags)
        ti = min(10.0, max(0.0, snapshot.threat_intel_score))
        # attack_path is metadata stub — always 0.0 (no path analysis)
        attack_path = 0.0

        dimensions = RiskDimensionScores(
            threat_intel=ti,
            compliance=compliance,
            identity=identity,
            exposure=exposure,
            attack_path=attack_path,
            cspm=cspm,
            criticality=criticality,
            kubernetes=kubernetes,
            runtime=runtime,
        )
        w = profile.to_dict()
        components = [
            RiskContribution(
                dimension=name,
                raw_score=dimensions.to_dict()[name],
                weight=w[name],
                weighted_score=round(dimensions.to_dict()[name] * w[name], 6),
                rationale=self._rationale(name, snapshot),
                category=self._category_for(name),
            )
            for name in w
            if w[name] > 0.0 or name == "attack_path"
        ]
        evidence = [
            RiskEvidence(
                evidence_id=f"cspm-{len(snapshot.open_finding_severities)}",
                source=RiskSource.CSPM,
                summary=f"{len(snapshot.open_finding_severities)} open findings",
                details={"severities": list(snapshot.open_finding_severities)},
            ),
            RiskEvidence(
                evidence_id="exposure",
                source=RiskSource.EXPOSURE,
                summary=f"network_exposure={snapshot.network_exposure}",
                details={
                    "public_accessibility": snapshot.public_accessibility,
                    "encryption_at_rest": snapshot.encryption_at_rest,
                    "lateral_movement_potential": snapshot.lateral_movement_potential,
                },
            ),
        ]
        return dimensions, components, evidence

    def overall(
        self,
        dimensions: RiskDimensionScores,
        weights: RiskWeightProfile | None = None,
    ) -> float:
        return compute_weighted_overall(dimensions, weights or RiskWeightProfile.default()).value

    @staticmethod
    def _cspm_score(severities: tuple[str, ...]) -> float:
        if not severities:
            return 0.0
        # Cap aggregated contribution — max of top findings with diminishing add
        ranked = sorted((severity_to_score(s) for s in severities), reverse=True)
        total = ranked[0]
        for idx, value in enumerate(ranked[1:5], start=1):
            total += value * (0.5**idx)
        return min(10.0, total)

    @staticmethod
    def _identity_score(privilege_level: str) -> float:
        mapping = {
            "NONE": 0.0,
            "LOW": 2.0,
            "MEDIUM": 5.0,
            "HIGH": 7.5,
            "ADMIN": 10.0,
        }
        return mapping.get(privilege_level.upper(), 3.0)

    @staticmethod
    def _exposure_score(
        *,
        network_exposure: str,
        public_accessibility: bool,
        encryption_at_rest: bool,
    ) -> float:
        score = 0.0
        exp = network_exposure.upper()
        if exp in {"PUBLIC", "INTERNET"}:
            score += 6.0
        elif exp in {"INTERNAL", "PRIVATE"}:
            score += 1.0
        if public_accessibility:
            score += 2.0
        if not encryption_at_rest:
            score += 2.0
        return min(10.0, score)

    @staticmethod
    def _k8s_score(k8s_security_score: float | None) -> float:
        if k8s_security_score is None:
            return 0.0
        # Invert 0..100 higher=better → 0..10 higher=worse
        return min(10.0, max(0.0, 10.0 * (1.0 - float(k8s_security_score) / 100.0)))

    @staticmethod
    def _runtime_score(severities: tuple[str, ...]) -> float:
        if not severities:
            return 0.0
        return min(10.0, max(severity_to_score(s) for s in severities))

    @staticmethod
    def _criticality_score(label: str, tags: tuple[tuple[str, str], ...]) -> float:
        tag_map = {k.lower(): v.lower() for k, v in tags}
        if tag_map.get("criticality") in {"critical", "tier0"} or label.upper() == "CRITICAL":
            return 10.0
        if label.upper() == "HIGH" or tag_map.get("criticality") == "high":
            return 7.5
        if label.upper() == "LOW":
            return 2.5
        return 5.0

    @staticmethod
    def _category_for(dimension: str) -> RiskCategory:
        mapping = {
            "threat_intel": RiskCategory.THREAT_INTEL,
            "compliance": RiskCategory.COMPLIANCE,
            "identity": RiskCategory.IDENTITY,
            "exposure": RiskCategory.EXPOSURE,
            "attack_path": RiskCategory.ATTACK_PATH,
            "cspm": RiskCategory.CONFIGURATION,
            "criticality": RiskCategory.BUSINESS_CRITICALITY,
            "kubernetes": RiskCategory.KUBERNETES,
            "runtime": RiskCategory.RUNTIME,
        }
        return mapping.get(dimension, RiskCategory.COMPOSITE)

    @staticmethod
    def _rationale(dimension: str, snapshot: RiskSignalSnapshot) -> str:
        if dimension == "cspm":
            return f"open_findings={len(snapshot.open_finding_severities)}"
        if dimension == "identity":
            return f"privilege_level={snapshot.privilege_level}"
        if dimension == "exposure":
            return f"network_exposure={snapshot.network_exposure}"
        if dimension == "kubernetes":
            return f"k8s_security_score={snapshot.k8s_security_score}"
        if dimension == "runtime":
            return f"runtime_events={len(snapshot.runtime_event_severities)}"
        if dimension == "attack_path":
            return "metadata_stub_no_path_analysis"
        if dimension == "compliance":
            return f"compliance_gap_ratio={snapshot.compliance_gap_ratio:.3f}"
        if dimension == "criticality":
            return f"business_criticality={snapshot.business_criticality}"
        if dimension == "threat_intel":
            return f"threat_intel_score={snapshot.threat_intel_score}"
        return dimension
