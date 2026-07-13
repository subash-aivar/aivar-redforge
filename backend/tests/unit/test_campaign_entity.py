"""Unit tests for the Campaign aggregate root (domain/campaigns/entity.py)."""

from __future__ import annotations

import pytest

from redforge.domain.campaigns.entity import Campaign
from redforge.domain.campaigns.events import (
    CampaignCancelled,
    CampaignCompleted,
    CampaignCreated,
    CampaignFailed,
    CampaignPaused,
    CampaignResumed,
    CampaignStarted,
)
from redforge.domain.campaigns.exceptions import (
    CampaignAlreadyTerminalError,
    CampaignNotPausedError,
    CampaignNotRunningError,
    EmptyCampaignTargetsError,
    InvalidCampaignTransitionError,
)
from redforge.domain.campaigns.value_objects import (
    CampaignMetrics,
    CampaignStatus,
    CampaignType,
    DriftSummary,
    TargetResult,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now


def _target_ids(n: int = 3) -> frozenset[EntityId]:
    return frozenset(EntityId.generate() for _ in range(n))


def _campaign(n_targets: int = 2) -> Campaign:
    return Campaign.create(
        organization_id=EntityId.generate(),
        policy_id=EntityId.generate(),
        campaign_type=CampaignType.MANUAL,
        target_ids=_target_ids(n_targets),
    )


def _metrics(campaign: Campaign) -> CampaignMetrics:
    return CampaignMetrics(
        total_targets=len(campaign.target_ids),
        successful_targets=len(campaign.target_ids),
        failed_targets=0,
        total_findings=2,
        mean_vulnerability_rate=0.5,
        total_duration_ms=1000,
    )


def _target_result(target_id: EntityId) -> TargetResult:
    return TargetResult(
        target_id=target_id,
        run_id=str(EntityId.generate()),
        status="completed",
        findings_count=1,
        vulnerability_rate=0.5,
        duration_ms=100,
    )


class TestCreate:
    def test_creates_pending_campaign(self) -> None:
        c = _campaign()
        assert c.status == CampaignStatus.PENDING

    def test_emits_created_event(self) -> None:
        c = _campaign()
        events = c.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], CampaignCreated)

    def test_empty_targets_raises(self) -> None:
        with pytest.raises(EmptyCampaignTargetsError):
            Campaign.create(
                organization_id=EntityId.generate(),
                policy_id=EntityId.generate(),
                campaign_type=CampaignType.MANUAL,
                target_ids=frozenset(),
            )

    def test_progress_initialised_from_target_count(self) -> None:
        c = Campaign.create(
            organization_id=EntityId.generate(),
            policy_id=EntityId.generate(),
            campaign_type=CampaignType.SMOKE,
            target_ids=_target_ids(5),
        )
        assert c.progress.total_targets == 5
        assert c.progress.pending_targets == 5
        assert c.progress.completion_pct == 0.0

    def test_unique_ids(self) -> None:
        assert _campaign().id != _campaign().id

    def test_default_configuration(self) -> None:
        c = _campaign()
        assert c.configuration.max_concurrent_targets == 5


class TestLifecycleTransitions:
    def test_pending_to_running(self) -> None:
        c = _campaign()
        c.collect_events()
        c.start()
        assert c.status == CampaignStatus.RUNNING
        assert c.started_at is not None
        events = c.collect_events()
        assert any(isinstance(e, CampaignStarted) for e in events)

    def test_cannot_start_twice(self) -> None:
        c = _campaign()
        c.start()
        with pytest.raises(InvalidCampaignTransitionError):
            c.start()

    def test_running_to_paused(self) -> None:
        c = _campaign()
        c.start()
        c.collect_events()
        c.pause()
        assert c.status == CampaignStatus.PAUSED
        assert c.paused_at is not None
        events = c.collect_events()
        assert any(isinstance(e, CampaignPaused) for e in events)

    def test_pause_requires_running(self) -> None:
        c = _campaign()
        with pytest.raises(CampaignNotRunningError):
            c.pause()

    def test_paused_to_running_via_resume(self) -> None:
        c = _campaign()
        c.start()
        c.pause()
        c.collect_events()
        c.resume()
        assert c.status == CampaignStatus.RUNNING
        assert c.paused_at is None
        events = c.collect_events()
        assert any(isinstance(e, CampaignResumed) for e in events)

    def test_resume_requires_paused(self) -> None:
        c = _campaign()
        c.start()
        with pytest.raises(CampaignNotPausedError):
            c.resume()

    def test_cancel_from_running(self) -> None:
        c = _campaign()
        c.start()
        c.collect_events()
        c.cancel("operator decision")
        assert c.status == CampaignStatus.CANCELLED
        assert c.is_terminal
        events = c.collect_events()
        assert any(isinstance(e, CampaignCancelled) for e in events)

    def test_cancel_from_pending(self) -> None:
        c = _campaign()
        c.collect_events()
        c.cancel()
        assert c.status == CampaignStatus.CANCELLED

    def test_cancel_terminal_raises(self) -> None:
        c = _campaign()
        c.start()
        c.cancel()
        with pytest.raises(CampaignAlreadyTerminalError):
            c.cancel()

    def test_complete_attaches_metrics(self) -> None:
        c = _campaign()
        c.start()
        m = _metrics(c)
        c.collect_events()
        c.complete(m)
        assert c.status == CampaignStatus.COMPLETED
        assert c.metrics is m
        assert c.completed_at is not None
        events = c.collect_events()
        assert any(isinstance(e, CampaignCompleted) for e in events)

    def test_complete_without_running_raises(self) -> None:
        c = _campaign()
        with pytest.raises(InvalidCampaignTransitionError):
            c.complete(_metrics(c))

    def test_fail_from_running(self) -> None:
        c = _campaign()
        c.start()
        c.collect_events()
        c.fail("executor crashed")
        assert c.status == CampaignStatus.FAILED
        assert c.is_terminal
        assert c.failure_reason == "executor crashed"
        events = c.collect_events()
        assert any(isinstance(e, CampaignFailed) for e in events)

    def test_fail_from_pending_raises(self) -> None:
        c = _campaign()
        with pytest.raises(InvalidCampaignTransitionError):
            c.fail("premature")


class TestProgressTracking:
    def test_record_target_completed_advances_progress(self) -> None:
        c = _campaign(n_targets=3)
        c.start()
        tid = next(iter(c.target_ids))
        c.collect_events()
        c.record_target_completed(_target_result(tid))
        assert c.progress.completed_targets == 1
        assert c.progress.pending_targets == 2

    def test_record_target_failed_advances_failed_count(self) -> None:
        c = _campaign(n_targets=2)
        c.start()
        tid = next(iter(c.target_ids))
        c.collect_events()
        c.record_target_failed(tid, "timeout")
        assert c.progress.failed_targets == 1

    def test_target_results_accumulate(self) -> None:
        c = _campaign(n_targets=2)
        c.start()
        for tid in list(c.target_ids):
            c.record_target_completed(_target_result(tid))
        assert len(c.target_results) == 2
        assert c.progress.is_complete

    def test_record_target_not_running_raises(self) -> None:
        c = _campaign()
        tid = next(iter(c.target_ids))
        with pytest.raises(InvalidCampaignTransitionError):
            c.record_target_completed(_target_result(tid))

    def test_completion_pct_halfway(self) -> None:
        c = _campaign(n_targets=4)
        c.start()
        tids = list(c.target_ids)
        c.record_target_completed(_target_result(tids[0]))
        c.record_target_completed(_target_result(tids[1]))
        assert c.progress.completion_pct == 50.0


class TestDriftSummary:
    def test_complete_with_drift_summary(self) -> None:
        c = Campaign.create(
            organization_id=EntityId.generate(),
            policy_id=EntityId.generate(),
            campaign_type=CampaignType.REGRESSION,
            target_ids=_target_ids(1),
            baseline_campaign_id=EntityId.generate(),
        )
        c.start()
        c.collect_events()
        drift = DriftSummary(
            baseline_campaign_id=EntityId.generate(),
            baseline_completed_at=utc_now(),
            new_findings_count=2,
            resolved_findings_count=0,
            vulnerability_rate_delta=0.15,
        )
        c.complete(_metrics(c), drift_summary=drift)
        assert c.drift_summary is not None
        assert c.drift_summary.regression_detected is True
        events = c.collect_events()
        completed_evt = next(e for e in events if isinstance(e, CampaignCompleted))
        assert completed_evt.regression_detected is True

    def test_no_regression_when_new_findings_zero(self) -> None:
        drift = DriftSummary(
            baseline_campaign_id=EntityId.generate(),
            baseline_completed_at=utc_now(),
            new_findings_count=0,
            resolved_findings_count=1,
            vulnerability_rate_delta=-0.1,
        )
        assert drift.regression_detected is False
        assert drift.improvement_detected is True


class TestEquality:
    def test_same_id_equal(self) -> None:
        c = _campaign()
        assert c == c

    def test_different_campaigns_not_equal(self) -> None:
        assert _campaign() != _campaign()

    def test_hashable(self) -> None:
        c1 = _campaign()
        c2 = _campaign()
        assert len({c1, c2}) == 2
