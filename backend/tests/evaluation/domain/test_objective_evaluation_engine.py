"""Domain tests for ObjectiveEvaluationEngine."""

from __future__ import annotations

from datetime import UTC, datetime

from evaluation.domain.services.objective_evaluation_engine import (
    ObjectiveEvaluationEngine,
)
from evaluation.domain.value_objects.enums import ObjectiveOutcome
from evaluation.domain.value_objects.evaluation_vos import (
    AttackActionRecord,
    DetectionFindingRecord,
    EvidenceRecord,
    ObjectiveSpec,
)


def test_detection_absent_achieved_when_no_findings() -> None:
    engine = ObjectiveEvaluationEngine()
    now = datetime.now(UTC)
    spec = ObjectiveSpec(
        objective_id="obj-1",
        objective_type="DetectionEvaded",
        is_required=True,
        condition_type="DetectionAbsent",
        parameters={"technique_id": "T1078"},
    )
    assessment = engine.evaluate(spec, [], [], [], now)
    assert assessment.outcome == ObjectiveOutcome.ACHIEVED


def test_detection_absent_failed_when_finding_present() -> None:
    engine = ObjectiveEvaluationEngine()
    now = datetime.now(UTC)
    spec = ObjectiveSpec(
        objective_id="obj-1",
        objective_type="DetectionEvaded",
        is_required=True,
        condition_type="DetectionAbsent",
        parameters={"technique_id": "T1078"},
    )
    findings = [
        DetectionFindingRecord(
            finding_id="f1",
            rule_id="r1",
            technique_id="T1078",
            asset_ref="h1",
            detected_at=now.isoformat(),
        )
    ]
    assessment = engine.evaluate(spec, [], findings, [], now)
    assert assessment.outcome == ObjectiveOutcome.FAILED


def test_attack_action_completed() -> None:
    engine = ObjectiveEvaluationEngine()
    now = datetime.now(UTC)
    spec = ObjectiveSpec(
        objective_id="obj-2",
        objective_type="AccessAchieved",
        is_required=True,
        condition_type="AttackActionCompleted",
        parameters={"technique_id": "T1078"},
    )
    actions = [
        AttackActionRecord(
            action_id="a1",
            operation_id="o1",
            technique_id="T1078",
            asset_ref="h1",
            started_at=now.isoformat(),
            completed_at=now.isoformat(),
            outcome="Success",
        )
    ]
    assessment = engine.evaluate(spec, actions, [], [], now)
    assert assessment.outcome == ObjectiveOutcome.ACHIEVED


def test_evidence_present() -> None:
    engine = ObjectiveEvaluationEngine()
    now = datetime.now(UTC)
    spec = ObjectiveSpec(
        objective_id="obj-3",
        objective_type="DataAccessed",
        is_required=True,
        condition_type="EvidencePresent",
        parameters={"evidence_type": "FileHash"},
    )
    evidence = [
        EvidenceRecord(
            evidence_id="e1",
            action_id="a1",
            evidence_type="FileHash",
            created_at=now.isoformat(),
        )
    ]
    assessment = engine.evaluate(spec, [], [], evidence, now)
    assert assessment.outcome == ObjectiveOutcome.ACHIEVED


def test_unknown_condition_is_inconclusive() -> None:
    engine = ObjectiveEvaluationEngine()
    now = datetime.now(UTC)
    spec = ObjectiveSpec(
        objective_id="obj-4",
        objective_type="CustomDefined",
        is_required=False,
        condition_type="UnknownFutureType",
        parameters={},
    )
    assessment = engine.evaluate(spec, [], [], [], now)
    assert assessment.outcome == ObjectiveOutcome.INCONCLUSIVE
