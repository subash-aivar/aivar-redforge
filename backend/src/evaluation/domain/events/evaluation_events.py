"""Evaluation domain events."""

from __future__ import annotations

from dataclasses import dataclass

from evaluation.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignEvaluationStarted(BaseDomainEvent):
    campaign_instance_id: str
    run_number: int


@dataclass(frozen=True, slots=True, kw_only=True)
class ObjectiveAssessmentCompleted(BaseDomainEvent):
    objective_id: str
    objective_type: str
    outcome: str           # ObjectiveOutcome value
    evidence_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionCoverageComputed(BaseDomainEvent):
    campaign_instance_id: str
    detection_coverage_percent: float
    techniques_executed: int
    techniques_detected: int
    late_detections_count: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignEvaluationCompleted(BaseDomainEvent):
    campaign_instance_id: str
    composite_outcome: str
    detection_coverage_percent: float
    objectives_achieved: int
    objectives_failed: int


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignEvaluationRequiresReview(BaseDomainEvent):
    """Inconclusive objectives require analyst judgment."""

    campaign_instance_id: str
    inconclusive_objective_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class MetricsSnapshotCreated(BaseDomainEvent):
    campaign_id: str
    run_number: int
    detection_coverage_percent: float
    technique_success_rate: float
    composite_outcome: str
