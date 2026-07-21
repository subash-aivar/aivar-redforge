"""CampaignEvaluation aggregate root — post-execution campaign evaluation."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from evaluation.domain.events.evaluation_events import (
    CampaignEvaluationCompleted,
    CampaignEvaluationRequiresReview,
    CampaignEvaluationStarted,
    DetectionCoverageComputed,
    ObjectiveAssessmentCompleted,
)
from evaluation.domain.exceptions.domain_exceptions import (
    EvaluationAlreadyComplete,
    InvalidEvaluationState,
    NoObjectivesRegistered,
    ObjectiveAlreadyAssessed,
    TenantMismatch,
)
from evaluation.domain.value_objects.enums import (
    CompositeOutcome,
    EvaluationState,
    ObjectiveOutcome,
)

if TYPE_CHECKING:
    from datetime import datetime

    from evaluation.domain.entities.evaluation_entities import (
        LateDetectionRecord,
        ObjectiveAssessment,
        TechniqueOutcomeRecord,
    )
    from evaluation.domain.events.base import BaseDomainEvent
    from evaluation.domain.value_objects.evaluation_vos import (
        CampaignInstanceRef,
        ComplianceMappingResult,
        EvaluationMetrics,
        KillChainProgressionMap,
        ObjectiveSpec,
    )
    from evaluation.domain.value_objects.identifiers import (
        CampaignEvaluationId,
        TenantId,
    )


class CampaignEvaluation:
    """Owns post-execution objective assessment and detection coverage.

    Created only on CampaignInstanceCompleted / CampaignInstanceFailed.
    CompositeOutcome is deterministic — no manual override.
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "assessments",
        "campaign_instance_ref",
        "compliance_mappings",
        "composite_outcome",
        "correlation_window_minutes",
        "evaluation_id",
        "execution_failed",
        "kill_chain_progression",
        "late_detections",
        "metrics",
        "objective_specs",
        "per_phase_coverage",
        "state",
        "technique_outcomes",
        "tenant_id",
    )

    def __init__(
        self,
        evaluation_id: CampaignEvaluationId,
        tenant_id: TenantId,
        campaign_instance_ref: CampaignInstanceRef,
        state: EvaluationState,
        objective_specs: list[ObjectiveSpec],
        assessments: list[ObjectiveAssessment],
        technique_outcomes: list[TechniqueOutcomeRecord],
        late_detections: list[LateDetectionRecord],
        metrics: EvaluationMetrics | None,
        composite_outcome: CompositeOutcome | None,
        kill_chain_progression: KillChainProgressionMap | None,
        compliance_mappings: list[ComplianceMappingResult],
        correlation_window_minutes: int,
        execution_failed: bool,
        version: int,
        per_phase_coverage: tuple[tuple[str, float], ...] = (),
    ) -> None:
        self.evaluation_id = evaluation_id
        self.tenant_id = tenant_id
        self.campaign_instance_ref = campaign_instance_ref
        self.state = state
        self.objective_specs = list(objective_specs)
        self.assessments = list(assessments)
        self.technique_outcomes = list(technique_outcomes)
        self.late_detections = list(late_detections)
        self.metrics = metrics
        self.composite_outcome = composite_outcome
        self.kill_chain_progression = kill_chain_progression
        self.compliance_mappings = list(compliance_mappings)
        self.correlation_window_minutes = correlation_window_minutes
        self.execution_failed = execution_failed
        self.per_phase_coverage = per_phase_coverage
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self) -> None:
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_mutable(self) -> None:
        if self.state == EvaluationState.COMPLETE:
            raise EvaluationAlreadyComplete(str(self.evaluation_id))

    @classmethod
    def start(
        cls,
        evaluation_id: CampaignEvaluationId,
        tenant_id: TenantId,
        campaign_instance_ref: CampaignInstanceRef,
        objective_specs: list[ObjectiveSpec],
        correlation_window_minutes: int,
        execution_failed: bool,
        now: datetime,
    ) -> CampaignEvaluation:
        from evaluation.domain.value_objects.evaluation_vos import EvaluationMetrics

        evaluation = cls(
            evaluation_id=evaluation_id,
            tenant_id=tenant_id,
            campaign_instance_ref=campaign_instance_ref,
            state=EvaluationState.EVALUATING,
            objective_specs=objective_specs,
            assessments=[],
            technique_outcomes=[],
            late_detections=[],
            metrics=EvaluationMetrics(),
            composite_outcome=None,
            kill_chain_progression=None,
            compliance_mappings=[],
            correlation_window_minutes=correlation_window_minutes,
            execution_failed=execution_failed,
            version=1,
        )
        evaluation._emit(
            CampaignEvaluationStarted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(evaluation_id),
                aggregate_type="CampaignEvaluation",
                campaign_instance_id=str(campaign_instance_ref.instance_id),
                run_number=campaign_instance_ref.run_number,
            )
        )
        return evaluation

    def record_assessment(
        self,
        tenant_id: TenantId,
        assessment: ObjectiveAssessment,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.state != EvaluationState.EVALUATING:
            raise InvalidEvaluationState(self.state.value, "record_assessment")

        existing = {a.objective_id for a in self.assessments}
        if assessment.objective_id in existing:
            # Idempotent: ObjectiveAssessmentCompleted per objective+instance
            raise ObjectiveAlreadyAssessed(assessment.objective_id)

        self.assessments.append(assessment)
        self._mutate()
        self._emit(
            ObjectiveAssessmentCompleted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evaluation_id),
                aggregate_type="CampaignEvaluation",
                objective_id=assessment.objective_id,
                objective_type=assessment.objective_type,
                outcome=assessment.outcome.value,
                evidence_count=len(assessment.evidence_refs),
            )
        )

    def record_coverage(
        self,
        tenant_id: TenantId,
        metrics: EvaluationMetrics,
        technique_outcomes: list[TechniqueOutcomeRecord],
        late_detections: list[LateDetectionRecord],
        techniques_executed: int,
        techniques_detected: int,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.state != EvaluationState.EVALUATING:
            raise InvalidEvaluationState(self.state.value, "record_coverage")

        self.metrics = metrics
        self.technique_outcomes = list(technique_outcomes)
        self.late_detections = list(late_detections)
        self._mutate()
        self._emit(
            DetectionCoverageComputed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evaluation_id),
                aggregate_type="CampaignEvaluation",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                detection_coverage_percent=metrics.detection_coverage_percent,
                techniques_executed=techniques_executed,
                techniques_detected=techniques_detected,
                late_detections_count=len(late_detections),
            )
        )

    def set_kill_chain_progression(
        self,
        tenant_id: TenantId,
        progression: KillChainProgressionMap,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.kill_chain_progression = progression
        self._mutate()

    def set_per_phase_coverage(
        self,
        tenant_id: TenantId,
        per_phase_coverage: tuple[tuple[str, float], ...],
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.per_phase_coverage = per_phase_coverage
        self._mutate()

    def set_compliance_mappings(
        self,
        tenant_id: TenantId,
        mappings: list[ComplianceMappingResult],
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.compliance_mappings = list(mappings)
        self._mutate()

    def complete(self, tenant_id: TenantId, now: datetime) -> None:
        """Seal assessments and compute deterministic CompositeOutcome."""
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.state != EvaluationState.EVALUATING:
            raise InvalidEvaluationState(self.state.value, "complete")
        if not self.assessments and self.objective_specs:
            raise NoObjectivesRegistered(str(self.evaluation_id))

        outcome = self._compute_composite_outcome()
        self.composite_outcome = outcome

        inconclusive_ids = tuple(
            a.objective_id for a in self.assessments if a.outcome == ObjectiveOutcome.INCONCLUSIVE
        )

        achieved = sum(1 for a in self.assessments if a.outcome == ObjectiveOutcome.ACHIEVED)
        failed = sum(1 for a in self.assessments if a.outcome == ObjectiveOutcome.FAILED)

        if self.metrics is not None:
            from evaluation.domain.value_objects.evaluation_vos import EvaluationMetrics

            phases = (
                tuple(self.kill_chain_progression.phases_covered)
                if self.kill_chain_progression
                else ()
            )
            self.metrics = EvaluationMetrics(
                detection_coverage_percent=self.metrics.detection_coverage_percent,
                technique_success_rate=self.metrics.technique_success_rate,
                evasion_rate=self.metrics.evasion_rate,
                mean_time_to_detect_seconds=self.metrics.mean_time_to_detect_seconds,
                actions_executed_count=self.metrics.actions_executed_count,
                actions_failed_count=self.metrics.actions_failed_count,
                objectives_achieved_count=achieved,
                objectives_failed_count=failed,
                campaign_duration_seconds=self.metrics.campaign_duration_seconds,
                kill_chain_phases_covered=phases,
            )

        if inconclusive_ids:
            self.state = EvaluationState.REQUIRES_REVIEW
            self._mutate()
            self._emit(
                CampaignEvaluationRequiresReview(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.evaluation_id),
                    aggregate_type="CampaignEvaluation",
                    campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                    inconclusive_objective_ids=inconclusive_ids,
                    reason="One or more objectives returned Inconclusive",
                )
            )
            return

        self.state = EvaluationState.COMPLETE
        self._mutate()
        coverage = self.metrics.detection_coverage_percent if self.metrics else 0.0
        self._emit(
            CampaignEvaluationCompleted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evaluation_id),
                aggregate_type="CampaignEvaluation",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                composite_outcome=outcome.value,
                detection_coverage_percent=coverage,
                objectives_achieved=achieved,
                objectives_failed=failed,
                kill_chain_phases=self._kill_chain_phase_tuples(),
                per_phase_coverage=self.per_phase_coverage,
            )
        )

    def mark_review_resolved(
        self,
        tenant_id: TenantId,
        now: datetime,
        documented_reason: str,
    ) -> None:
        """Analyst resolves RequiresReview — does not freely override CompositeOutcome."""
        self._assert_tenant(tenant_id)
        if self.state != EvaluationState.REQUIRES_REVIEW:
            raise InvalidEvaluationState(self.state.value, "mark_review_resolved")
        if not documented_reason.strip():
            raise InvalidEvaluationState(
                self.state.value, "mark_review_resolved: documented_reason required"
            )

        if self.composite_outcome is None:
            self.composite_outcome = self._compute_composite_outcome()

        self.state = EvaluationState.COMPLETE
        self._mutate()
        coverage = self.metrics.detection_coverage_percent if self.metrics else 0.0
        achieved = sum(1 for a in self.assessments if a.outcome == ObjectiveOutcome.ACHIEVED)
        failed = sum(1 for a in self.assessments if a.outcome == ObjectiveOutcome.FAILED)
        self._emit(
            CampaignEvaluationCompleted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.evaluation_id),
                aggregate_type="CampaignEvaluation",
                campaign_instance_id=str(self.campaign_instance_ref.instance_id),
                composite_outcome=self.composite_outcome.value,
                detection_coverage_percent=coverage,
                objectives_achieved=achieved,
                objectives_failed=failed,
                kill_chain_phases=self._kill_chain_phase_tuples(),
                per_phase_coverage=self.per_phase_coverage,
            )
        )

    def _kill_chain_phase_tuples(self) -> tuple[tuple[str, str], ...]:
        if self.kill_chain_progression is None:
            return ()
        return tuple(
            (p.phase_name, f"{p.tasks_completed}/{p.tasks_planned}")
            for p in self.kill_chain_progression.phase_outcomes
        )

    def _compute_composite_outcome(self) -> CompositeOutcome:
        """ADR-M30-007 deterministic formula."""
        if self.execution_failed and not self.assessments:
            return CompositeOutcome.EXECUTION_FAILED

        required_specs = {s.objective_id for s in self.objective_specs if s.is_required}
        if not required_specs:
            # Treat all as required when none flagged
            required_specs = {s.objective_id for s in self.objective_specs}

        required_assessments = [a for a in self.assessments if a.objective_id in required_specs]
        if not required_assessments:
            if self.execution_failed:
                return CompositeOutcome.EXECUTION_FAILED
            return CompositeOutcome.INCONCLUSIVE

        achieved = [a for a in required_assessments if a.outcome == ObjectiveOutcome.ACHIEVED]
        inconclusive = [
            a for a in required_assessments if a.outcome == ObjectiveOutcome.INCONCLUSIVE
        ]

        if inconclusive and len(achieved) < len(required_assessments):
            # Partial inconclusive handled at complete() via RequiresReview;
            # still compute a provisional composite for the review path.
            pass

        if len(achieved) == len(required_assessments):
            return CompositeOutcome.FULL_SUCCESS

        ratio = len(achieved) / len(required_assessments)
        if ratio >= 0.5:
            return CompositeOutcome.PARTIAL_SUCCESS

        if self.execution_failed:
            return CompositeOutcome.EXECUTION_FAILED

        return CompositeOutcome.OBJECTIVES_MISSED
