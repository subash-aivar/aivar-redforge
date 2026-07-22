from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ThreatHuntCandidateDTO:
    candidate_id: str
    tenant_id: str
    status: str
    confidence_score: float
    detection_rule_format: str
    technique_coverage: list[str]
    anomaly_signal_count: int
