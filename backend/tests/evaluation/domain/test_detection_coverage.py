"""Domain tests for DetectionCoverageCalculator — Phase 5 quality gates."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from evaluation.domain.services.detection_coverage_calculator import (
    DetectionCoverageCalculator,
)
from evaluation.domain.value_objects.evaluation_vos import (
    AttackActionRecord,
    DetectionCorrelationConfig,
    DetectionFindingRecord,
)


def _action(
    action_id: str,
    technique_id: str,
    started: datetime,
    outcome: str = "Success",
    asset: str = "host-1",
) -> AttackActionRecord:
    return AttackActionRecord(
        action_id=action_id,
        operation_id=f"op-{action_id}",
        technique_id=technique_id,
        asset_ref=asset,
        started_at=started.isoformat(),
        completed_at=(started + timedelta(minutes=1)).isoformat(),
        outcome=outcome,
    )


def _finding(
    finding_id: str,
    technique_id: str,
    detected: datetime,
    asset: str = "host-1",
    linked_action_id: str | None = None,
) -> DetectionFindingRecord:
    return DetectionFindingRecord(
        finding_id=finding_id,
        rule_id="rule-1",
        technique_id=technique_id,
        asset_ref=asset,
        detected_at=detected.isoformat(),
        linked_action_id=linked_action_id,
    )


def test_zero_findings_for_actions_yields_zero_coverage() -> None:
    calc = DetectionCoverageCalculator()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    actions = [_action(f"a{i}", f"T{i}", now) for i in range(100)]
    result = calc.compute(actions, [], DetectionCorrelationConfig())
    assert result.metrics.detection_coverage_percent == 0.0
    assert result.techniques_detected == 0
    assert result.techniques_executed == 100


def test_finding_within_30_min_counted_as_detected() -> None:
    calc = DetectionCoverageCalculator()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    actions = [_action("a1", "T1078", now)]
    findings = [_finding("f1", "T1078", now + timedelta(minutes=15))]
    result = calc.compute(actions, findings, DetectionCorrelationConfig())
    assert result.metrics.detection_coverage_percent == 100.0
    assert result.techniques_detected == 1
    assert result.technique_outcomes[0].detected is True
    assert result.technique_outcomes[0].evaded is False


def test_finding_outside_window_is_late_detection() -> None:
    calc = DetectionCoverageCalculator()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    actions = [_action("a1", "T1078", now)]
    findings = [_finding("f1", "T1078", now + timedelta(minutes=45))]
    result = calc.compute(
        actions, findings, DetectionCorrelationConfig(correlation_window_minutes=30)
    )
    assert result.metrics.detection_coverage_percent == 0.0
    assert len(result.late_detections) == 1
    assert result.late_detections[0].finding_id == "f1"


def test_graph_linked_finding_overrides_window() -> None:
    calc = DetectionCoverageCalculator()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    actions = [_action("a1", "T1078", now)]
    # 2 hours later but explicitly linked
    findings = [
        _finding(
            "f1",
            "T1078",
            now + timedelta(hours=2),
            linked_action_id="a1",
        )
    ]
    result = calc.compute(actions, findings, DetectionCorrelationConfig())
    assert result.metrics.detection_coverage_percent == 100.0
    assert result.technique_outcomes[0].detected is True


def test_partial_coverage_across_techniques() -> None:
    calc = DetectionCoverageCalculator()
    now = datetime(2026, 7, 21, 12, 0, tzinfo=UTC)
    actions = [
        _action("a1", "T1078", now),
        _action("a2", "T1059", now),
    ]
    findings = [_finding("f1", "T1078", now + timedelta(minutes=5))]
    result = calc.compute(actions, findings, DetectionCorrelationConfig())
    assert result.metrics.detection_coverage_percent == 50.0
    assert result.techniques_detected == 1
    assert result.techniques_executed == 2
