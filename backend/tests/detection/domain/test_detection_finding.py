"""DetectionFinding aggregate, FindingKey, and deduplication tests."""

from __future__ import annotations

from datetime import timedelta

import pytest

from detection.domain.events.finding_events import (
    DetectionFindingClosed,
    DetectionFindingConfirmed,
    DetectionFindingEscalated,
    DetectionFindingMarkedFalsePositive,
    DetectionFindingProduced,
    DetectionFindingSuppressed,
    DetectionFindingTriaged,
)
from detection.domain.exceptions.domain_exceptions import (
    FindingLifecycleBlocked,
    InvalidArgument,
    InvalidStateTransition,
)
from detection.domain.services.finding_dedup import FindingDeduplicator
from detection.domain.value_objects.enums import (
    FindingConfidence,
    FindingSeverity,
    FindingState,
)
from detection.domain.value_objects.execution_finding import (
    AnalystNote,
    AssetRef,
    DedupWindow,
    DetectionExecutionRef,
    EscalationRef,
    FindingKey,
    TelemetryFingerprint,
    TelemetrySignalRef,
)
from tests.detection.phase3_helpers import (
    advance,
    make_execution,
    make_finding,
    make_fingerprint,
)


def test_produce_emits_event(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now)
    events = finding.pop_events()
    assert isinstance(events[0], DetectionFindingProduced)
    assert finding.state == FindingState.NEW


def test_finding_key_stable() -> None:
    fp = TelemetryFingerprint.from_fields({"a": 1, "b": 2})
    k1 = FindingKey.compute(rule_id="r1", asset_ref="a1", telemetry_fingerprint=fp)
    k2 = FindingKey.compute(rule_id="r1", asset_ref="a1", telemetry_fingerprint=fp)
    assert k1 == k2
    assert len(str(k1)) == 64


def test_finding_key_differs_by_asset() -> None:
    fp = make_fingerprint()
    k1 = FindingKey.compute(rule_id="r", asset_ref="a1", telemetry_fingerprint=fp)
    k2 = FindingKey.compute(rule_id="r", asset_ref="a2", telemetry_fingerprint=fp)
    assert k1 != k2


def test_fingerprint_from_fields_order_independent() -> None:
    a = TelemetryFingerprint.from_fields({"z": 1, "a": 2})
    b = TelemetryFingerprint.from_fields({"a": 2, "z": 1})
    assert a == b


def test_triage_confirm_close(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    finding.triage(tenant_id=tenant_id, analyst="a@x", now=now)
    assert isinstance(finding.pop_events()[0], DetectionFindingTriaged)
    finding.confirm(tenant_id=tenant_id, analyst="a@x", now=now)
    assert isinstance(finding.pop_events()[0], DetectionFindingConfirmed)
    finding.close(tenant_id=tenant_id, reason="done", now=now)
    assert isinstance(finding.pop_events()[0], DetectionFindingClosed)


def test_false_positive(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    finding.mark_false_positive(
        tenant_id=tenant_id,
        analyst="a@x",
        justification="benign admin tool",
        now=now,
    )
    assert finding.state == FindingState.FALSE_POSITIVE
    assert isinstance(finding.pop_events()[0], DetectionFindingMarkedFalsePositive)


def test_suppress(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    finding.suppress(
        tenant_id=tenant_id, analyst="a@x", justification="noise", now=now
    )
    assert isinstance(finding.pop_events()[0], DetectionFindingSuppressed)


def test_escalate(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    finding.escalate(
        tenant_id=tenant_id,
        analyst="a@x",
        escalation_ref=EscalationRef(investigation_id="inv-1", escalated_at=now),
        now=now,
    )
    assert finding.state == FindingState.ESCALATED_TO_INVESTIGATION
    assert isinstance(finding.pop_events()[0], DetectionFindingEscalated)


def test_fp_requires_justification(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    with pytest.raises(InvalidArgument):
        finding.mark_false_positive(
            tenant_id=tenant_id, analyst="a", justification=" ", now=now
        )


def test_cannot_triage_closed(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    finding.close(tenant_id=tenant_id, reason="x", now=now)
    with pytest.raises(InvalidStateTransition):
        finding.triage(tenant_id=tenant_id, analyst="a", now=now)


def test_dedup_within_window_updates_last_seen(tenant_id, now) -> None:
    existing = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    later = advance(now, minutes=5)
    decision = FindingDeduplicator().decide(
        existing=existing,
        now=later,
        tenant_id=tenant_id,
        finding_key=existing.finding_key,
        rule_ref=existing.rule_ref,
        execution_ref=existing.execution_ref,
        asset_ref=existing.asset_ref,
        telemetry_signal=existing.telemetry_signal,
        telemetry_fingerprint=existing.telemetry_fingerprint,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        observed_at=later,
    )
    assert decision.deduplicated is True
    assert decision.created is False
    assert existing.last_seen_at == later


def test_dedup_outside_window_reopens(tenant_id, now) -> None:
    existing = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    later = advance(now, minutes=20)
    decision = FindingDeduplicator(
        DedupWindow(duration=timedelta(minutes=15))
    ).decide(
        existing=existing,
        now=later,
        tenant_id=tenant_id,
        finding_key=existing.finding_key,
        rule_ref=existing.rule_ref,
        execution_ref=existing.execution_ref,
        asset_ref=existing.asset_ref,
        telemetry_signal=existing.telemetry_signal,
        telemetry_fingerprint=existing.telemetry_fingerprint,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        observed_at=later,
    )
    assert decision.created is True
    assert decision.finding.reopened_from == existing.finding_id


def test_dedup_no_existing_creates(tenant_id, now) -> None:
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    fp = make_fingerprint()
    key = FindingKey.compute(
        rule_id=execution.rule_ref.rule_id,
        asset_ref="asset-x",
        telemetry_fingerprint=fp,
    )
    decision = FindingDeduplicator().decide(
        existing=None,
        now=now,
        tenant_id=tenant_id,
        finding_key=key,
        rule_ref=execution.rule_ref,
        execution_ref=DetectionExecutionRef(str(execution.execution_id)),
        asset_ref=AssetRef("asset-x"),
        telemetry_signal=TelemetrySignalRef("sig"),
        telemetry_fingerprint=fp,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.MEDIUM,
        observed_at=now,
    )
    assert decision.created is True
    assert isinstance(decision.finding.pop_events()[0], DetectionFindingProduced)


def test_touch_last_seen_blocked_when_closed(tenant_id, now) -> None:
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    finding.close(tenant_id=tenant_id, reason="x", now=now)
    with pytest.raises(FindingLifecycleBlocked):
        finding.touch_last_seen(tenant_id=tenant_id, now=now)


@pytest.mark.parametrize("severity", list(FindingSeverity))
def test_all_severities(tenant_id, now, severity: FindingSeverity) -> None:
    # severity set at produce — recreate
    execution = make_execution(tenant_id=tenant_id, now=now, pop_events=True)
    fp = make_fingerprint({"sev": severity.value})
    key = FindingKey.compute(
        rule_id=execution.rule_ref.rule_id,
        asset_ref="a",
        telemetry_fingerprint=fp,
    )
    from detection.domain.aggregates.detection_finding import DetectionFinding

    f = DetectionFinding.produce(
        tenant_id=tenant_id,
        finding_key=key,
        rule_ref=execution.rule_ref,
        execution_ref=DetectionExecutionRef(str(execution.execution_id)),
        asset_ref=AssetRef("a"),
        telemetry_signal=TelemetrySignalRef("s"),
        telemetry_fingerprint=fp,
        severity=severity,
        confidence=FindingConfidence.LOW,
        observed_at=now,
        now=now,
    )
    assert f.severity == severity


@pytest.mark.parametrize(
    "path",
    [
        ("triage", FindingState.TRIAGED),
        ("confirm", FindingState.CONFIRMED),
        ("fp", FindingState.FALSE_POSITIVE),
        ("suppress", FindingState.SUPPRESSED),
        ("escalate", FindingState.ESCALATED_TO_INVESTIGATION),
        ("close", FindingState.CLOSED),
    ],
)
def test_lifecycle_paths_from_new(tenant_id, now, path) -> None:
    action, expected = path
    finding = make_finding(tenant_id=tenant_id, now=now, pop_events=True)
    if action == "triage":
        finding.triage(tenant_id=tenant_id, analyst="a", now=now)
    elif action == "confirm":
        finding.confirm(tenant_id=tenant_id, analyst="a", now=now)
    elif action == "fp":
        finding.mark_false_positive(
            tenant_id=tenant_id, analyst="a", justification="j", now=now
        )
    elif action == "suppress":
        finding.suppress(
            tenant_id=tenant_id, analyst="a", justification="j", now=now
        )
    elif action == "escalate":
        finding.escalate(
            tenant_id=tenant_id,
            analyst="a",
            escalation_ref=EscalationRef("inv"),
            now=now,
        )
    else:
        finding.close(tenant_id=tenant_id, reason="r", now=now)
    assert finding.state == expected


def test_analyst_note_validation() -> None:
    with pytest.raises(InvalidArgument):
        AnalystNote(text="")


def test_dedup_window_must_be_positive() -> None:
    with pytest.raises(InvalidArgument):
        DedupWindow(duration=timedelta(seconds=0))
