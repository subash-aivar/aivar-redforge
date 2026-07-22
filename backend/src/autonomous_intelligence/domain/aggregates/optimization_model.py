"""OptimizationModel aggregate — ADR-M36-005."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from autonomous_intelligence.domain.events.intelligence_events import ModelDeployed, ModelDeprecated
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AccuracyThresholdNotMet,
    DomainInvariantViolation,
    InvalidModelTransition,
    TenantMismatch,
)
from autonomous_intelligence.domain.value_objects.enums import ModelStatus, SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import ModelId, TenantId

ACCURACY_THRESHOLDS: dict[SuggestionTargetType, dict[str, float]] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: {"precision": 0.75, "recall": 0.70},
    SuggestionTargetType.CAMPAIGN_SCENARIO: {"relevance_score": 0.65},
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: {"structure_score": 0.70},
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: {"rank_correlation": 0.60},
}


class OptimizationModel:
    __slots__ = (
        "_pending_events",
        "accuracy_metrics",
        "conformity_assessment_ref",
        "created_at",
        "deployed_at",
        "feedback_sample_count",
        "model_id",
        "model_version",
        "retraining_threshold",
        "status",
        "target_type",
        "tenant_id",
    )

    def __init__(
        self,
        model_id: ModelId,
        tenant_id: TenantId,
        target_type: SuggestionTargetType,
        model_version: int,
        status: ModelStatus,
        *,
        accuracy_metrics: dict[str, float] | None = None,
        conformity_assessment_ref: str | None = None,
        feedback_sample_count: int = 0,
        retraining_threshold: int = 50,
        created_at: datetime | None = None,
        deployed_at: datetime | None = None,
    ) -> None:
        self.model_id = model_id
        self.tenant_id = tenant_id
        self.target_type = target_type
        self.model_version = model_version
        self.status = status
        self.accuracy_metrics = dict(accuracy_metrics or {})
        self.conformity_assessment_ref = conformity_assessment_ref
        self.feedback_sample_count = feedback_sample_count
        self.retraining_threshold = retraining_threshold
        self.created_at = created_at or datetime.now(UTC)
        self.deployed_at = deployed_at
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def start_training(
        cls,
        tenant_id: TenantId,
        target_type: SuggestionTargetType,
        model_id: str,
        model_version: int,
    ) -> OptimizationModel:
        return cls(ModelId(model_id), tenant_id, target_type, model_version, ModelStatus.TRAINING)

    def mark_validating(self, metrics: dict[str, float]) -> None:
        if self.status != ModelStatus.TRAINING:
            raise InvalidModelTransition(self.status.value)
        self.status = ModelStatus.VALIDATING
        self.accuracy_metrics = dict(metrics)

    def fail(self) -> None:
        if self.status not in {ModelStatus.TRAINING, ModelStatus.VALIDATING}:
            raise InvalidModelTransition(self.status.value)
        self.status = ModelStatus.FAILED

    def deploy(self, tenant_id: TenantId, conformity_assessment_ref: str) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if self.status != ModelStatus.VALIDATING:
            raise InvalidModelTransition(self.status.value)
        if not conformity_assessment_ref:
            raise DomainInvariantViolation("conformity_assessment_ref required for deploy")
        thresholds = ACCURACY_THRESHOLDS[self.target_type]
        for key, minimum in thresholds.items():
            if self.accuracy_metrics.get(key, 0.0) < minimum:
                raise AccuracyThresholdNotMet(f"{key}={self.accuracy_metrics.get(key)} < {minimum}")
        now = datetime.now(UTC)
        self.status = ModelStatus.DEPLOYED
        self.conformity_assessment_ref = conformity_assessment_ref
        self.deployed_at = now
        self._pending_events.append(
            ModelDeployed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.model_id),
                model_id=str(self.model_id),
                target_type=self.target_type.value,
                model_version=self.model_version,
                accuracy_metrics=dict(self.accuracy_metrics),
            )
        )

    def deprecate(self, tenant_id: TenantId, superseded_by_version: int) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if self.status != ModelStatus.DEPLOYED:
            raise InvalidModelTransition(self.status.value)
        self.status = ModelStatus.DEPRECATED
        self._pending_events.append(
            ModelDeprecated(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.model_id),
                model_id=str(self.model_id),
                superseded_by_version=superseded_by_version,
            )
        )

    def record_feedback(self) -> None:
        self.feedback_sample_count += 1

    def needs_retraining(self) -> bool:
        return self.feedback_sample_count >= self.retraining_threshold
