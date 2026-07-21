"""Aggregate tests for CampaignEvaluation — composite outcome formula."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from evaluation.domain.aggregates.campaign_evaluation import CampaignEvaluation
from evaluation.domain.entities.evaluation_entities import ObjectiveAssessment
from evaluation.domain.exceptions.domain_exceptions import EvaluationAlreadyComplete
from evaluation.domain.value_objects.enums import (
    CompositeOutcome,
    EvaluationState,
    ObjectiveOutcome,
)
from evaluation.domain.value_objects.evaluation_vos import (
    CampaignInstanceRef,
    EvaluationMetrics,
    ObjectiveSpec,
)
from evaluation.domain.value_objects.identifiers import (
    CampaignEvaluationId,
    ObjectiveAssessmentId,
    TenantId,
)


def _start(
    specs: list[ObjectiveSpec] | None = None,
    execution_failed: bool = False,
) -> tuple[CampaignEvaluation, TenantId, datetime]:
    tenant = TenantId(uuid4())
    now = datetime.now(UTC)
    specs = specs or [
        ObjectiveSpec(
            objective_id="o1",
            objective_type="AccessAchieved",
            is_required=True,
            condition_type="AttackActionCompleted",
        ),
        ObjectiveSpec(
            objective_id="o2",
            objective_type="DetectionEvaded",
            is_required=True,
            condition_type="DetectionAbsent",
        ),
    ]
    evaluation = CampaignEvaluation.start(
        evaluation_id=CampaignEvaluationId.generate(),
        tenant_id=tenant,
        campaign_instance_ref=CampaignInstanceRef(
            instance_id=uuid4(),
            campaign_id=uuid4(),
            tenant_id=tenant.value,
            run_number=1,
        ),
        objective_specs=specs,
        correlation_window_minutes=30,
        execution_failed=execution_failed,
        now=now,
    )
    return evaluation, tenant, now


def _assessment(objective_id: str, outcome: ObjectiveOutcome) -> ObjectiveAssessment:
    return ObjectiveAssessment(
        assessment_id=ObjectiveAssessmentId.generate(),
        objective_id=objective_id,
        objective_type="AccessAchieved",
        outcome=outcome,
        evidence_refs=[],
        reason="test",
        assessed_at=datetime.now(UTC),
    )


def test_full_success_when_all_required_achieved() -> None:
    evaluation, tenant, now = _start()
    evaluation.record_assessment(tenant, _assessment("o1", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_assessment(tenant, _assessment("o2", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_coverage(
        tenant,
        EvaluationMetrics(detection_coverage_percent=50.0),
        [],
        [],
        techniques_executed=2,
        techniques_detected=1,
        now=now,
    )
    evaluation.complete(tenant, now)
    assert evaluation.state == EvaluationState.COMPLETE
    assert evaluation.composite_outcome == CompositeOutcome.FULL_SUCCESS


def test_partial_success_at_50_percent() -> None:
    evaluation, tenant, now = _start()
    evaluation.record_assessment(tenant, _assessment("o1", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_assessment(tenant, _assessment("o2", ObjectiveOutcome.FAILED), now)
    evaluation.record_coverage(tenant, EvaluationMetrics(), [], [], 0, 0, now)
    evaluation.complete(tenant, now)
    assert evaluation.composite_outcome == CompositeOutcome.PARTIAL_SUCCESS


def test_objectives_missed_below_50() -> None:
    specs = [
        ObjectiveSpec(
            objective_id=f"o{i}",
            objective_type="AccessAchieved",
            is_required=True,
            condition_type="AttackActionCompleted",
        )
        for i in range(3)
    ]
    evaluation, tenant, now = _start(specs=specs)
    evaluation.record_assessment(tenant, _assessment("o0", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_assessment(tenant, _assessment("o1", ObjectiveOutcome.FAILED), now)
    evaluation.record_assessment(tenant, _assessment("o2", ObjectiveOutcome.FAILED), now)
    evaluation.record_coverage(tenant, EvaluationMetrics(), [], [], 0, 0, now)
    evaluation.complete(tenant, now)
    assert evaluation.composite_outcome == CompositeOutcome.OBJECTIVES_MISSED


def test_inconclusive_requires_review() -> None:
    evaluation, tenant, now = _start()
    evaluation.record_assessment(tenant, _assessment("o1", ObjectiveOutcome.INCONCLUSIVE), now)
    evaluation.record_assessment(tenant, _assessment("o2", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_coverage(tenant, EvaluationMetrics(), [], [], 0, 0, now)
    evaluation.complete(tenant, now)
    assert evaluation.state == EvaluationState.REQUIRES_REVIEW


def test_sealed_after_complete() -> None:
    evaluation, tenant, now = _start()
    evaluation.record_assessment(tenant, _assessment("o1", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_assessment(tenant, _assessment("o2", ObjectiveOutcome.ACHIEVED), now)
    evaluation.record_coverage(tenant, EvaluationMetrics(), [], [], 0, 0, now)
    evaluation.complete(tenant, now)
    with pytest.raises(EvaluationAlreadyComplete):
        evaluation.record_assessment(tenant, _assessment("o3", ObjectiveOutcome.ACHIEVED), now)
