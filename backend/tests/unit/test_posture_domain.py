"""Unit tests for the Security Posture bounded context — domain layer.

Covers:
  - Value objects: SnapshotMetrics, ConfigurationFingerprint, DriftEvent,
    ValidationRegressionDetail, ValidationTrend, SecurityPostureScore,
    ValidationWindow, BaselinePolicy, TrendPolicy, PostureLevel
  - Domain events
  - ValidationSnapshot aggregate lifecycle
  - ValidationBaseline aggregate lifecycle (establish, supersede, expire, revoke)
  - Exception classes
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from redforge.domain.posture.entity import ValidationBaseline, ValidationSnapshot
from redforge.domain.posture.events import (
    BaselineEstablished,
    BaselineSuperseded,
    RegressionDetected,
    SnapshotCreated,
)
from redforge.domain.posture.exceptions import (
    BaselineAlreadyTerminalError,
    BaselineNotFoundError,
    InsufficientHistoryError,
    SnapshotNotFoundError,
)
from redforge.domain.posture.value_objects import (
    BaselinePolicy,
    BaselineStatus,
    ConfigurationFingerprint,
    DriftEvent,
    DriftType,
    PostureLevel,
    SnapshotMetrics,
    TrendPolicy,
    ValidationWindow,
)

# ─── Fixtures ──────────────────────────────────────────────────────────────────


def _metrics(
    vuln_rate: float = 0.10,
    total: int = 10,
    findings: int = 1,
) -> SnapshotMetrics:
    return SnapshotMetrics(
        vulnerability_rate=vuln_rate,
        total_attacks=total,
        finding_count=findings,
        duration_ms=5000,
        pass_rate=1.0 - vuln_rate,
    )


def _fingerprint(
    model: str = "gpt-4o",
    provider: str = "openai",
    prompt_hash: str = "abc123",
    categories: frozenset[str] | None = None,
) -> ConfigurationFingerprint:
    return ConfigurationFingerprint(
        model=model,
        provider=provider,
        system_prompt_hash=prompt_hash,
        attack_categories=categories or frozenset({"prompt_injection", "jailbreak"}),
        tool_names=("search", "calculator"),
    )


def _snapshot(
    target_id: str = "target-1",
    org_id: str = "org-1",
    vuln_rate: float = 0.10,
) -> ValidationSnapshot:
    snap, _ = ValidationSnapshot.create(
        organization_id=org_id,
        target_id=target_id,
        run_id="run-1",
        metrics=_metrics(vuln_rate),
        fingerprint=_fingerprint(),
    )
    return snap


def _baseline(
    snapshot: ValidationSnapshot | None = None,
    policy: BaselinePolicy | None = None,
) -> tuple[ValidationBaseline, list]:
    if snapshot is None:
        snapshot = _snapshot()
    return ValidationBaseline.establish(
        organization_id=snapshot.organization_id,
        target_id=snapshot.target_id,
        snapshot=snapshot,
        policy=policy or BaselinePolicy(),
    )


# ─── SnapshotMetrics ───────────────────────────────────────────────────────────


class TestSnapshotMetrics:
    def test_valid_construction(self) -> None:
        m = _metrics()
        assert m.vulnerability_rate == 0.10
        assert m.total_attacks == 10

    def test_rejects_vuln_rate_out_of_bounds(self) -> None:
        with pytest.raises(ValueError):
            SnapshotMetrics(
                vulnerability_rate=1.5, total_attacks=10, finding_count=1, duration_ms=100
            )

    def test_rejects_negative_attacks(self) -> None:
        with pytest.raises(ValueError):
            SnapshotMetrics(
                vulnerability_rate=0.0, total_attacks=-1, finding_count=0, duration_ms=100
            )

    def test_has_critical_findings_false(self) -> None:
        m = _metrics()
        assert not m.has_critical_findings

    def test_has_critical_findings_true(self) -> None:
        m = SnapshotMetrics(
            vulnerability_rate=0.5, total_attacks=10, finding_count=2, duration_ms=1000,
            critical_finding_count=1
        )
        assert m.has_critical_findings

    def test_severity_weighted_rate_no_findings(self) -> None:
        m = SnapshotMetrics(
            vulnerability_rate=0.3, total_attacks=10, finding_count=0, duration_ms=1000
        )
        assert m.severity_weighted_rate == 0.3

    def test_severity_weighted_rate_amplified(self) -> None:
        m = SnapshotMetrics(
            vulnerability_rate=0.3, total_attacks=10, finding_count=2, duration_ms=1000,
            critical_finding_count=2
        )
        assert m.severity_weighted_rate > 0.3


# ─── ConfigurationFingerprint ─────────────────────────────────────────────────


class TestConfigurationFingerprint:
    def test_diff_empty_when_identical(self) -> None:
        fp = _fingerprint()
        assert fp.diff(fp) == []

    def test_diff_detects_model_change(self) -> None:
        a = _fingerprint(model="gpt-4o")
        b = _fingerprint(model="gpt-4-turbo")
        assert DriftType.MODEL in a.diff(b)

    def test_diff_detects_provider_change(self) -> None:
        a = _fingerprint(provider="openai")
        b = _fingerprint(provider="anthropic")
        assert DriftType.PROVIDER in a.diff(b)

    def test_diff_detects_prompt_change(self) -> None:
        a = _fingerprint(prompt_hash="aaa")
        b = _fingerprint(prompt_hash="bbb")
        assert DriftType.SYSTEM_PROMPT in a.diff(b)

    def test_diff_detects_category_change(self) -> None:
        a = _fingerprint(categories=frozenset({"pi"}))
        b = _fingerprint(categories=frozenset({"pi", "jailbreak"}))
        assert DriftType.ATTACK_COVERAGE in a.diff(b)

    def test_diff_multiple(self) -> None:
        a = _fingerprint(model="gpt-4o", provider="openai")
        b = _fingerprint(model="claude-3", provider="anthropic")
        diffs = a.diff(b)
        assert DriftType.MODEL in diffs
        assert DriftType.PROVIDER in diffs


# ─── DriftEvent ───────────────────────────────────────────────────────────────


class TestDriftEvent:
    def test_has_model_drift(self) -> None:
        e = DriftEvent(
            source_snapshot_id="s1",
            target_snapshot_id="s2",
            drift_types=(DriftType.MODEL,),
            description="model changed",
        )
        assert e.has_model_drift
        assert not e.has_prompt_drift

    def test_is_significant_with_model(self) -> None:
        e = DriftEvent(
            source_snapshot_id="s1",
            target_snapshot_id="s2",
            drift_types=(DriftType.MODEL,),
            description="",
        )
        assert e.is_significant

    def test_is_not_significant_with_tools_only(self) -> None:
        e = DriftEvent(
            source_snapshot_id="s1",
            target_snapshot_id="s2",
            drift_types=(DriftType.TOOL_CONFIGURATION,),
            description="",
        )
        assert not e.is_significant


# ─── PostureLevel ─────────────────────────────────────────────────────────────


class TestPostureLevel:
    @pytest.mark.parametrize("rate, expected", [
        (0.0, PostureLevel.EXCELLENT),
        (0.04, PostureLevel.EXCELLENT),
        (0.05, PostureLevel.GOOD),
        (0.14, PostureLevel.GOOD),
        (0.15, PostureLevel.FAIR),
        (0.29, PostureLevel.FAIR),
        (0.30, PostureLevel.POOR),
        (0.49, PostureLevel.POOR),
        (0.50, PostureLevel.CRITICAL),
        (1.0, PostureLevel.CRITICAL),
    ])
    def test_from_vulnerability_rate(self, rate: float, expected: PostureLevel) -> None:
        assert PostureLevel.from_vulnerability_rate(rate) == expected


# ─── ValidationWindow ─────────────────────────────────────────────────────────


class TestValidationWindow:
    def test_last_7_days(self) -> None:
        w = ValidationWindow.last_7_days()
        assert w.duration == timedelta(days=7)
        assert w.last_n_snapshots is None

    def test_last_n(self) -> None:
        w = ValidationWindow.last_n(50)
        assert w.last_n_snapshots == 50

    def test_rejects_n_less_than_1(self) -> None:
        with pytest.raises(ValueError):
            ValidationWindow(last_n_snapshots=0)

    def test_rejects_min_snapshots_less_than_1(self) -> None:
        with pytest.raises(ValueError):
            ValidationWindow(min_snapshots=0)


# ─── BaselinePolicy ───────────────────────────────────────────────────────────


class TestBaselinePolicy:
    def test_defaults(self) -> None:
        p = BaselinePolicy()
        assert p.auto_establish is True
        assert p.stability_window == 1
        assert p.max_age_days == 90

    def test_rejects_stability_window_zero(self) -> None:
        with pytest.raises(ValueError):
            BaselinePolicy(stability_window=0)

    def test_rejects_negative_tolerance(self) -> None:
        with pytest.raises(ValueError):
            BaselinePolicy(stability_tolerance=-0.1)


# ─── TrendPolicy ──────────────────────────────────────────────────────────────


class TestTrendPolicy:
    def test_defaults(self) -> None:
        p = TrendPolicy()
        assert p.degradation_threshold == 0.05
        assert p.min_snapshots_for_trend == 2

    def test_rejects_min_snapshots_1(self) -> None:
        with pytest.raises(ValueError):
            TrendPolicy(min_snapshots_for_trend=1)


# ─── ValidationSnapshot ───────────────────────────────────────────────────────


class TestValidationSnapshot:
    def test_create_returns_snapshot_and_event(self) -> None:
        snap, events = ValidationSnapshot.create(
            organization_id="org-1",
            target_id="target-1",
            run_id="run-1",
            metrics=_metrics(),
            fingerprint=_fingerprint(),
        )
        assert snap.organization_id == "org-1"
        assert snap.target_id == "target-1"
        assert snap.run_id == "run-1"
        assert len(events) == 1
        assert isinstance(events[0], SnapshotCreated)

    def test_snapshot_event_has_correct_data(self) -> None:
        _snap, events = ValidationSnapshot.create(
            organization_id="org-A",
            target_id="target-B",
            run_id="run-C",
            metrics=_metrics(0.25),
            fingerprint=_fingerprint(),
        )
        ev = events[0]
        assert isinstance(ev, SnapshotCreated)
        assert ev.organization_id == "org-A"
        assert ev.target_id == "target-B"
        assert ev.vulnerability_rate == pytest.approx(0.25)

    def test_snapshot_id_is_nonempty(self) -> None:
        snap = _snapshot()
        assert snap.id
        assert len(snap.id) > 10

    def test_snapshot_vulnerability_rate_matches_metrics(self) -> None:
        snap = _snapshot(vuln_rate=0.42)
        assert snap.vulnerability_rate == pytest.approx(0.42)

    def test_snapshot_has_no_extra_slots(self) -> None:
        snap = _snapshot()
        # __slots__ defined — cannot add arbitrary attributes
        with pytest.raises(AttributeError):
            snap.not_a_real_attr = "x"  # type: ignore[attr-defined]

    def test_snapshot_repr(self) -> None:
        snap = _snapshot()
        assert "ValidationSnapshot" in repr(snap)


# ─── ValidationBaseline ───────────────────────────────────────────────────────


class TestValidationBaseline:
    def test_establish_returns_active_baseline_and_event(self) -> None:
        snap = _snapshot()
        baseline, events = ValidationBaseline.establish(
            organization_id=snap.organization_id,
            target_id=snap.target_id,
            snapshot=snap,
            policy=BaselinePolicy(),
        )
        assert baseline.is_active()
        assert baseline.status == BaselineStatus.ACTIVE
        assert len(events) == 1
        assert isinstance(events[0], BaselineEstablished)

    def test_baseline_event_has_correct_data(self) -> None:
        snap = _snapshot(org_id="org-X", target_id="target-Y")
        _baseline, events = ValidationBaseline.establish(
            organization_id="org-X",
            target_id="target-Y",
            snapshot=snap,
            policy=BaselinePolicy(),
            auto_established=True,
        )
        ev = events[0]
        assert isinstance(ev, BaselineEstablished)
        assert ev.organization_id == "org-X"
        assert ev.target_id == "target-Y"
        assert ev.auto_established is True

    def test_supersede_marks_baseline_superseded(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        assert baseline.is_active()

        events = baseline.supersede("new-baseline-id")
        assert baseline.status == BaselineStatus.SUPERSEDED
        assert not baseline.is_active()
        assert len(events) == 1
        assert isinstance(events[0], BaselineSuperseded)

    def test_supersede_event_links_old_to_new(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        events = baseline.supersede("new-baseline-id")
        ev = events[0]
        assert isinstance(ev, BaselineSuperseded)
        assert ev.old_baseline_id == baseline.id
        assert ev.new_baseline_id == "new-baseline-id"

    def test_expire_marks_baseline_expired(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        baseline.expire()
        assert baseline.status == BaselineStatus.EXPIRED

    def test_revoke_marks_baseline_revoked(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        baseline.revoke()
        assert baseline.status == BaselineStatus.REVOKED

    def test_cannot_supersede_terminal_baseline(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        baseline.expire()
        with pytest.raises(BaselineAlreadyTerminalError):
            baseline.supersede("other-id")

    def test_cannot_expire_revoked_baseline(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        baseline.revoke()
        with pytest.raises(BaselineAlreadyTerminalError):
            baseline.expire()

    def test_is_expired_by_age_with_fresh_baseline(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap, policy=BaselinePolicy(max_age_days=90))
        assert not baseline.is_expired_by_age()

    def test_baseline_vulnerability_rate_matches_snapshot(self) -> None:
        snap = _snapshot(vuln_rate=0.33)
        baseline, _ = _baseline(snap)
        assert baseline.vulnerability_rate == pytest.approx(0.33)

    def test_baseline_snapshot_id_matches(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        assert baseline.snapshot_id == snap.id

    def test_baseline_repr(self) -> None:
        snap = _snapshot()
        baseline, _ = _baseline(snap)
        assert "ValidationBaseline" in repr(baseline)


# ─── Exceptions ───────────────────────────────────────────────────────────────


class TestPostureExceptions:
    def test_baseline_not_found_message(self) -> None:
        exc = BaselineNotFoundError("org-1", "target-1")
        assert "org-1" in str(exc)
        assert "target-1" in str(exc)

    def test_insufficient_history(self) -> None:
        exc = InsufficientHistoryError("target-x", required=5, available=2)
        assert exc.required == 5
        assert exc.available == 2
        assert "target-x" in str(exc)

    def test_snapshot_not_found(self) -> None:
        exc = SnapshotNotFoundError("snap-abc")
        assert "snap-abc" in str(exc)


# ─── Domain Events ────────────────────────────────────────────────────────────


class TestPostureDomainEvents:
    def test_snapshot_created_fields(self) -> None:
        ev = SnapshotCreated(
            event_id="e1",
            snapshot_id="s1",
            organization_id="o1",
            target_id="t1",
            run_id="r1",
            vulnerability_rate=0.15,
        )
        assert ev.vulnerability_rate == pytest.approx(0.15)
        assert ev.occurred_at is not None

    def test_baseline_established_fields(self) -> None:
        ev = BaselineEstablished(
            event_id="e2",
            baseline_id="b1",
            organization_id="o1",
            target_id="t1",
            snapshot_id="s1",
            auto_established=True,
        )
        assert ev.auto_established is True

    def test_regression_detected_fields(self) -> None:
        ev = RegressionDetected(
            event_id="e3",
            snapshot_id="s1",
            baseline_id="b1",
            organization_id="o1",
            target_id="t1",
            vulnerability_rate_delta=0.12,
            severity="high",
        )
        assert ev.vulnerability_rate_delta == pytest.approx(0.12)
