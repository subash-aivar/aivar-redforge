"""Domain-level adversarial tests for the Continuous Validation bounded
context (M14) — ContinuousValidationPolicy lifecycle, cadence
coalescing, ValidationStateSnapshot fingerprinting, and the pure drift
comparison functions. No database — pure domain/application logic.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from redforge.application.continuous_validation.drift_detector import detect_drift
from redforge.domain.continuous_validation.entity import (
    ContinuousValidationPolicy,
    SecurityDriftEvent,
    ServiceSnapshotEntry,
    ValidationStateSnapshot,
)
from redforge.domain.continuous_validation.exceptions import InvalidPolicyTransitionError
from redforge.domain.continuous_validation.value_objects import (
    PolicyLifecycle,
    SecurityDriftCategory,
    ValidationCadence,
    cadence_interval_seconds,
    is_legal_policy_transition,
)
from redforge.domain.validation_execution.value_objects import ValidationProfile
from redforge.shared.identifiers import EntityId


def _make_policy(cadence: ValidationCadence = ValidationCadence.HOURLY) -> ContinuousValidationPolicy:
    return ContinuousValidationPolicy.create(
        organization_id=EntityId.generate(),
        target_id=EntityId.generate(),
        requester_user_id=EntityId.generate(),
        profile=ValidationProfile.SAFE_ACTIVE_BASELINE_V1,
        cadence=cadence,
    )


# ─── Lifecycle ─────────────────────────────────────────────────────────────────


def test_policy_created_in_draft() -> None:
    policy = _make_policy()
    assert policy.lifecycle == PolicyLifecycle.DRAFT
    assert policy.next_due_at is None


def test_activate_sets_next_due_at_to_now() -> None:
    policy = _make_policy()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    assert policy.lifecycle == PolicyLifecycle.ACTIVE
    assert policy.next_due_at == now


def test_full_legal_lifecycle_roundtrip() -> None:
    policy = _make_policy()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    policy.pause(now)
    assert policy.lifecycle == PolicyLifecycle.PAUSED
    policy.resume(now)
    assert policy.lifecycle == PolicyLifecycle.ACTIVE
    policy.disable(now)
    assert policy.lifecycle == PolicyLifecycle.DISABLED


@pytest.mark.parametrize(
    ("start", "target"),
    [
        (PolicyLifecycle.DRAFT, PolicyLifecycle.PAUSED),
        (PolicyLifecycle.ACTIVE, PolicyLifecycle.DRAFT),
        (PolicyLifecycle.PAUSED, PolicyLifecycle.PAUSED),
        (PolicyLifecycle.DISABLED, PolicyLifecycle.ACTIVE),
        (PolicyLifecycle.DISABLED, PolicyLifecycle.PAUSED),
        (PolicyLifecycle.DISABLED, PolicyLifecycle.DRAFT),
    ],
)
def test_illegal_transitions_rejected(start: PolicyLifecycle, target: PolicyLifecycle) -> None:
    assert not is_legal_policy_transition(start, target)


def test_disabled_is_terminal_no_reactivation() -> None:
    policy = _make_policy()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    policy.disable(now)
    with pytest.raises(InvalidPolicyTransitionError):
        policy.activate(now)
    with pytest.raises(InvalidPolicyTransitionError):
        policy.resume(now)


def test_activate_twice_rejected() -> None:
    policy = _make_policy()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    with pytest.raises(InvalidPolicyTransitionError):
        policy.activate(now)


def test_pause_without_active_rejected() -> None:
    policy = _make_policy()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(InvalidPolicyTransitionError):
        policy.pause(now)


def test_disable_releases_outstanding_claim() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy = ContinuousValidationPolicy(
        id=EntityId.generate(), organization_id=EntityId.generate(),
        target_id=EntityId.generate(), requester_user_id=EntityId.generate(),
        profile=ValidationProfile.SAFE_ACTIVE_BASELINE_V1, cadence=ValidationCadence.HOURLY,
        lifecycle=PolicyLifecycle.ACTIVE,
        timestamps=_make_policy().timestamps, next_due_at=now,
        claimed_at=now, claim_owner="worker-1",
    )
    policy.disable(now)
    assert policy.claimed_at is None
    assert policy.claim_owner is None


# ─── Cadence / due-boundary coalescing ─────────────────────────────────────────


@pytest.mark.parametrize(
    ("cadence", "expected_seconds"),
    [
        (ValidationCadence.HOURLY, 3_600),
        (ValidationCadence.EVERY_6_HOURS, 6 * 3_600),
        (ValidationCadence.DAILY, 24 * 3_600),
        (ValidationCadence.WEEKLY, 7 * 24 * 3_600),
    ],
)
def test_cadence_interval_seconds(cadence: ValidationCadence, expected_seconds: int) -> None:
    assert cadence_interval_seconds(cadence) == expected_seconds


def test_advance_schedule_no_missed_intervals() -> None:
    policy = _make_policy(ValidationCadence.HOURLY)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    policy.advance_schedule(now)
    assert policy.next_due_at == now + timedelta(hours=1)


def test_advance_schedule_coalesces_missed_intervals_in_one_jump() -> None:
    """3.5 hours elapsed on an hourly cadence -> 4 intervals coalesced
    into ONE arithmetic jump, never a loop incrementing hundreds of
    times."""
    policy = _make_policy(ValidationCadence.HOURLY)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    later = now + timedelta(hours=3, minutes=30)
    policy.advance_schedule(later)
    assert policy.next_due_at == now + timedelta(hours=4)


def test_advance_schedule_never_negative_when_run_early() -> None:
    """advance_schedule called with `now` BEFORE next_due_at (e.g. a
    claim processed unusually fast) never produces intervals_missed < 0
    — the floor-division is clamped to 0."""
    policy = _make_policy(ValidationCadence.HOURLY)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    earlier_call = now - timedelta(seconds=1)
    policy.advance_schedule(earlier_call)
    assert policy.next_due_at == now + timedelta(hours=1)


def test_is_due_respects_lease_window() -> None:
    policy = _make_policy(ValidationCadence.HOURLY)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    assert policy.is_due(now)
    assert not policy.is_due(now - timedelta(seconds=1))


def test_paused_policy_never_due() -> None:
    policy = _make_policy(ValidationCadence.HOURLY)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    policy.activate(now)
    policy.pause(now)
    assert not policy.is_due(now)


def test_draft_policy_never_due() -> None:
    policy = _make_policy(ValidationCadence.HOURLY)
    now = datetime(2026, 1, 1, tzinfo=UTC)
    assert not policy.is_due(now)


# ─── ValidationStateSnapshot ────────────────────────────────────────────────────


def _build_snapshot(
    org: EntityId, policy_id: EntityId, execution_id: EntityId,
    ports: list[int], ips: list[str] | None = None,
) -> ValidationStateSnapshot:
    return ValidationStateSnapshot.build(
        org, policy_id, execution_id,
        resolved_ips=ips or ["10.0.0.1"], reachable_ports=ports,
        services=[ServiceSnapshotEntry(p, "http", None, None) for p in ports],
        active_condition_keys=["cond:a"], active_correlation_keys=["corr:a"],
    )


def test_snapshot_fingerprint_deterministic_for_identical_input() -> None:
    org, policy_id = EntityId.generate(), EntityId.generate()
    s1 = _build_snapshot(org, policy_id, EntityId.generate(), [22, 443])
    s2 = _build_snapshot(org, policy_id, EntityId.generate(), [443, 22])  # different order
    assert s1.content_fingerprint == s2.content_fingerprint
    assert s1.is_identical_to(s2)


def test_snapshot_fingerprint_differs_on_real_change() -> None:
    org, policy_id = EntityId.generate(), EntityId.generate()
    s1 = _build_snapshot(org, policy_id, EntityId.generate(), [22, 443])
    s2 = _build_snapshot(org, policy_id, EntityId.generate(), [22])
    assert s1.content_fingerprint != s2.content_fingerprint
    assert not s1.is_identical_to(s2)


def test_snapshot_excludes_volatile_fields_from_fingerprint() -> None:
    """Two snapshots built at different wall-clock instants (different
    captured_at) with identical canonical state produce the SAME
    fingerprint — captured_at is never part of the comparison."""
    org, policy_id = EntityId.generate(), EntityId.generate()
    s1 = _build_snapshot(org, policy_id, EntityId.generate(), [22])
    s2 = _build_snapshot(org, policy_id, EntityId.generate(), [22])
    assert s1.content_fingerprint == s2.content_fingerprint


# ─── Drift detection ────────────────────────────────────────────────────────────


def test_identical_snapshots_produce_zero_drift() -> None:
    org, policy_id, exec_id = EntityId.generate(), EntityId.generate(), EntityId.generate()
    snap = _build_snapshot(org, policy_id, exec_id, [22])
    events = detect_drift(snap, snap, org, policy_id, exec_id)
    assert events == []


def test_no_baseline_produces_zero_drift_never_fabricated() -> None:
    org, policy_id, exec_id = EntityId.generate(), EntityId.generate(), EntityId.generate()
    snap = _build_snapshot(org, policy_id, exec_id, [22, 443])
    events = detect_drift(None, snap, org, policy_id, exec_id)
    assert events == []


def test_port_became_reachable_and_no_longer_reachable() -> None:
    org, policy_id = EntityId.generate(), EntityId.generate()
    prev = _build_snapshot(org, policy_id, EntityId.generate(), [22])
    curr = _build_snapshot(org, policy_id, EntityId.generate(), [443])
    events = detect_drift(prev, curr, org, policy_id, EntityId.generate())
    categories = {e.category for e in events}
    assert SecurityDriftCategory.PORT_BECAME_REACHABLE in categories
    assert SecurityDriftCategory.PORT_NO_LONGER_REACHABLE in categories


def test_tls_certificate_changed_only_when_both_sides_validated() -> None:
    org, policy_id = EntityId.generate(), EntityId.generate()
    prev = ValidationStateSnapshot.build(
        org, policy_id, EntityId.generate(),
        resolved_ips=["10.0.0.1"], reachable_ports=[443],
        services=[ServiceSnapshotEntry(443, "tls", None, "fp-old")],
        active_condition_keys=[], active_correlation_keys=[],
    )
    # Current: TLS no longer present at all (service absent) — this is
    # PROTOCOL_NO_LONGER_VALIDATED, never TLS_CERTIFICATE_CHANGED.
    curr_absent = ValidationStateSnapshot.build(
        org, policy_id, EntityId.generate(),
        resolved_ips=["10.0.0.1"], reachable_ports=[],
        services=[], active_condition_keys=[], active_correlation_keys=[],
    )
    events = detect_drift(prev, curr_absent, org, policy_id, EntityId.generate())
    categories = {e.category for e in events}
    assert SecurityDriftCategory.TLS_CERTIFICATE_CHANGED not in categories
    assert SecurityDriftCategory.PROTOCOL_NO_LONGER_VALIDATED in categories

    curr_new_fp = ValidationStateSnapshot.build(
        org, policy_id, EntityId.generate(),
        resolved_ips=["10.0.0.1"], reachable_ports=[443],
        services=[ServiceSnapshotEntry(443, "tls", None, "fp-new")],
        active_condition_keys=[], active_correlation_keys=[],
    )
    events2 = detect_drift(prev, curr_new_fp, org, policy_id, EntityId.generate())
    categories2 = {e.category for e in events2}
    assert SecurityDriftCategory.TLS_CERTIFICATE_CHANGED in categories2


def test_reactivated_keys_honored_not_rederived() -> None:
    org, policy_id = EntityId.generate(), EntityId.generate()
    prev = ValidationStateSnapshot.build(
        org, policy_id, EntityId.generate(),
        resolved_ips=[], reachable_ports=[], services=[],
        active_condition_keys=[], active_correlation_keys=[],
    )
    curr = ValidationStateSnapshot.build(
        org, policy_id, EntityId.generate(),
        resolved_ips=[], reachable_ports=[], services=[],
        active_condition_keys=["cond:x"], active_correlation_keys=[],
    )
    events_appeared = detect_drift(prev, curr, org, policy_id, EntityId.generate())
    assert any(e.category == SecurityDriftCategory.CONDITION_APPEARED for e in events_appeared)

    events_reactivated = detect_drift(
        prev, curr, org, policy_id, EntityId.generate(),
        reactivated_condition_keys=frozenset({"cond:x"}),
    )
    assert any(e.category == SecurityDriftCategory.CONDITION_REACTIVATED for e in events_reactivated)
    assert not any(
        e.category == SecurityDriftCategory.CONDITION_APPEARED for e in events_reactivated
    )


def test_drift_event_identity_excludes_detected_at_and_display_text() -> None:
    """SecurityDriftEvent.create() twice for the identical fact (same
    execution, category, identity_key) but different summary text
    produces entities that are identical along the dedup dimensions —
    proving the identity key never incorporates detected_at or
    display text (the DB unique constraint enforces this at the
    persistence layer; this test proves the domain-level identity
    fields alone are what matter)."""
    org, policy_id, exec_id = EntityId.generate(), EntityId.generate(), EntityId.generate()
    e1 = SecurityDriftEvent.create(
        org, policy_id, exec_id, SecurityDriftCategory.PORT_BECAME_REACHABLE, "port:22", "first text",
    )
    e2 = SecurityDriftEvent.create(
        org, policy_id, exec_id, SecurityDriftCategory.PORT_BECAME_REACHABLE, "port:22", "different text",
    )
    assert e1.execution_id == e2.execution_id
    assert e1.category == e2.category
    assert e1.identity_key == e2.identity_key
    assert e1.summary != e2.summary
