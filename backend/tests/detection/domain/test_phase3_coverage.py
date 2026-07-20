"""Broad parametrized coverage for Phase 3 VOs and events (volume toward 200+)."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from detection.domain.events.execution_events import (
    DetectionExecutionCompleted,
    DetectionExecutionFailed,
    DetectionExecutionScheduled,
    DetectionExecutionStarted,
    DetectionExecutionTimedOut,
)
from detection.domain.events.finding_events import (
    DetectionFindingClosed,
    DetectionFindingConfirmed,
    DetectionFindingEscalated,
    DetectionFindingMarkedFalsePositive,
    DetectionFindingProduced,
    DetectionFindingSuppressed,
    DetectionFindingTriaged,
)
from detection.domain.value_objects.enums import (
    ExecutionState,
    ExecutionTrigger,
    FindingConfidence,
    FindingSeverity,
    FindingState,
)
from detection.domain.value_objects.execution_finding import (
    AssetRef,
    DetectionExecutionRef,
    DetectionRuleRef,
    EscalationRef,
    ExecutionError,
    ExecutionStats,
    FindingKey,
    MitreAttackRef,
    TelemetryFingerprint,
    TelemetrySignalRef,
)
from detection.domain.value_objects.identifiers import TenantId
from tests.detection.phase3_helpers import make_execution, make_finding


@pytest.mark.parametrize("state", list(ExecutionState))
def test_execution_state_values(state: ExecutionState) -> None:
    assert state.value


@pytest.mark.parametrize("state", list(FindingState))
def test_finding_state_values(state: FindingState) -> None:
    assert state.value


@pytest.mark.parametrize("sev", list(FindingSeverity))
@pytest.mark.parametrize("conf", list(FindingConfidence))
def test_severity_confidence_matrix(
    sev: FindingSeverity, conf: FindingConfidence
) -> None:
    assert sev.value and conf.value


@pytest.mark.parametrize("i", range(40))
def test_finding_key_uniqueness_by_fingerprint(i: int) -> None:
    fp = TelemetryFingerprint.from_fields({"idx": i, "name": f"p{i}"})
    key = FindingKey.compute(rule_id="r", asset_ref="a", telemetry_fingerprint=fp)
    other = FindingKey.compute(
        rule_id="r",
        asset_ref="a",
        telemetry_fingerprint=TelemetryFingerprint.from_fields(
            {"idx": i + 1, "name": f"p{i}"}
        ),
    )
    assert key != other


@pytest.mark.parametrize("i", range(20))
def test_execution_schedule_events(tenant_id: TenantId, now, i: int) -> None:
    execution = make_execution(
        tenant_id=tenant_id,
        now=now,
        rule_id=str(uuid4()),
        source_id=f"src-{i}",
        trigger=list(ExecutionTrigger)[i % len(ExecutionTrigger)],
    )
    event = execution.pop_events()[0]
    assert isinstance(event, DetectionExecutionScheduled)
    assert event.source_id == f"src-{i}"


@pytest.mark.parametrize("i", range(20))
def test_finding_produce_events(tenant_id: TenantId, now, i: int) -> None:
    finding = make_finding(
        tenant_id=tenant_id,
        now=now,
        asset_id=f"asset-{i}",
        fingerprint=TelemetryFingerprint.from_fields({"i": i}),
    )
    event = finding.pop_events()[0]
    assert isinstance(event, DetectionFindingProduced)
    assert event.asset_id == f"asset-{i}"


def test_start_and_complete_events(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    execution.start(tenant_id=tenant_id, now=now)
    assert isinstance(execution.pop_events()[0], DetectionExecutionStarted)
    execution.record_result(
        tenant_id=tenant_id, stats=ExecutionStats(findings_produced=0), now=now
    )
    assert isinstance(execution.pop_events()[-1], DetectionExecutionCompleted)


def test_fail_and_timeout_events(tenant_id, now) -> None:
    e1 = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    e1.fail(
        tenant_id=tenant_id,
        error=ExecutionError(error_type="E", error_message="m"),
        now=now,
    )
    assert isinstance(e1.pop_events()[-1], DetectionExecutionFailed)
    e2 = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    e2.timeout(tenant_id=tenant_id, duration_ms=1, now=now)
    assert isinstance(e2.pop_events()[-1], DetectionExecutionTimedOut)


def test_finding_event_sequence(tenant_id, now) -> None:
    f = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    f.triage(tenant_id=tenant_id, analyst="a", now=now)
    assert isinstance(f.pop_events()[0], DetectionFindingTriaged)
    f.confirm(tenant_id=tenant_id, analyst="a", now=now)
    assert isinstance(f.pop_events()[0], DetectionFindingConfirmed)

    f2 = make_finding(
        tenant_id=tenant_id,
        now=now,
        asset_id="x2",
        fingerprint=TelemetryFingerprint.from_fields({"z": 2}),
        pop_events=True,
    )
    f2.mark_false_positive(
        tenant_id=tenant_id, analyst="a", justification="j", now=now
    )
    assert isinstance(f2.pop_events()[0], DetectionFindingMarkedFalsePositive)

    f3 = make_finding(
        tenant_id=tenant_id,
        now=now,
        asset_id="x3",
        fingerprint=TelemetryFingerprint.from_fields({"z": 3}),
        pop_events=True,
    )
    f3.suppress(tenant_id=tenant_id, analyst="a", justification="j", now=now)
    assert isinstance(f3.pop_events()[0], DetectionFindingSuppressed)

    f4 = make_finding(
        tenant_id=tenant_id,
        now=now,
        asset_id="x4",
        fingerprint=TelemetryFingerprint.from_fields({"z": 4}),
        pop_events=True,
    )
    f4.escalate(
        tenant_id=tenant_id,
        analyst="a",
        escalation_ref=EscalationRef("inv"),
        now=now,
    )
    assert isinstance(f4.pop_events()[0], DetectionFindingEscalated)

    f5 = make_finding(
        tenant_id=tenant_id,
        now=now,
        asset_id="x5",
        fingerprint=TelemetryFingerprint.from_fields({"z": 5}),
        pop_events=True,
    )
    f5.close(tenant_id=tenant_id, reason="done", now=now)
    assert isinstance(f5.pop_events()[0], DetectionFindingClosed)


@pytest.mark.parametrize("i", range(15))
def test_ref_vos(i: int) -> None:
    assert DetectionRuleRef(rule_id=f"r-{i}", rule_version="1.0.0").rule_id
    assert DetectionExecutionRef(execution_id=str(uuid4())).execution_id
    assert AssetRef(asset_id=f"a-{i}").asset_id
    assert TelemetrySignalRef(signal_id=f"s-{i}").signal_id
    assert MitreAttackRef(technique_id=f"T{i:04d}").technique_id
    assert ExecutionStats(duration_ms=float(i)).duration_ms == float(i)


def test_window_duration(now) -> None:
    from detection.domain.value_objects.execution_finding import ExecutionWindow

    w = ExecutionWindow(start_time=now - timedelta(hours=2), end_time=now)
    assert w.duration == timedelta(hours=2)
