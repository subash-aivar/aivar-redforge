"""DTOs for evaluation context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ObjectiveAssessmentDTO:
    objective_id: str
    objective_type: str
    outcome: str
    evidence_refs: list[str]
    reason: str


@dataclass(frozen=True, slots=True)
class TechniqueOutcomeDTO:
    technique_id: str
    succeeded: bool
    detected: bool
    evaded: bool


@dataclass(frozen=True, slots=True)
class EvaluationDTO:
    evaluation_id: str
    tenant_id: str
    campaign_instance_id: str
    campaign_id: str
    run_number: int
    state: str
    composite_outcome: str | None
    detection_coverage_percent: float
    technique_success_rate: float
    evasion_rate: float
    mean_time_to_detect_seconds: float | None
    objectives_achieved: int
    objectives_failed: int
    correlation_window_minutes: int
    late_detections_count: int
    assessments: list[ObjectiveAssessmentDTO] = field(default_factory=list)
    technique_outcomes: list[TechniqueOutcomeDTO] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class MetricsSnapshotDTO:
    snapshot_id: str
    campaign_id: str
    run_number: int
    snapshot_timestamp: datetime
    detection_coverage_percent: float
    technique_success_rate: float
    evasion_rate: float
    composite_outcome: str


@dataclass(frozen=True, slots=True)
class DetectionCoverageTrendDTO:
    """Trend across consecutive campaign runs."""

    campaign_id: str
    run_count: int
    coverage_values: list[float]
    trend_direction: str  # "better" | "worse" | "same"
    latest_coverage: float
