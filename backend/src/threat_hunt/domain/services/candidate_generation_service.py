from __future__ import annotations

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    TenantId,
)


class CandidateGenerationService:
    def create(
        self,
        tenant_id: TenantId,
        signals: tuple[AnomalySignalRef, ...],
        techniques: tuple[AttckTechniqueRef, ...],
        logic_draft: str,
        confidence: float,
        fmt: DetectionRuleFormat = DetectionRuleFormat.SIGMA,
    ) -> ThreatHuntCandidate:
        return ThreatHuntCandidate.create(
            tenant_id, signals, techniques, logic_draft, fmt, confidence
        )
