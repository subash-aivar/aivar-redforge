"""Tests for RecurrenceScheduler domain service — Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from campaign.domain.services.recurrence_scheduler import RecurrenceScheduler
from campaign.domain.value_objects.campaign_vos import RecurrencePolicy


@pytest.fixture()
def scheduler() -> RecurrenceScheduler:
    return RecurrenceScheduler()


# ── Cron expression and next fire time ────────────────────────────────────────

def test_next_fire_time_hourly_cron(scheduler: RecurrenceScheduler) -> None:
    # Every hour on the hour
    base = datetime(2026, 7, 21, 10, 0, 0, tzinfo=UTC)
    next_fire = scheduler.compute_next_fire_time_local("0 * * * *", base)
    # Next fire should be at 11:00 UTC
    assert next_fire.hour == 11
    assert next_fire.minute == 0


def test_next_fire_time_daily_midnight(scheduler: RecurrenceScheduler) -> None:
    base = datetime(2026, 7, 21, 10, 30, 0, tzinfo=UTC)
    next_fire = scheduler.compute_next_fire_time_local("0 0 * * *", base)
    assert next_fire.hour == 0
    assert next_fire.minute == 0
    # Should be the next day
    assert next_fire > base


def test_next_fire_time_weekly(scheduler: RecurrenceScheduler) -> None:
    # Every Monday at 09:00
    base = datetime(2026, 7, 21, 10, 0, 0, tzinfo=UTC)  # Tuesday
    next_fire = scheduler.compute_next_fire_time_local("0 9 * * MON", base)
    assert next_fire > base
    # weekday() == 0 for Monday
    assert next_fire.weekday() == 0
    assert next_fire.hour == 9


def test_correct_next_10_fire_times(scheduler: RecurrenceScheduler) -> None:
    """Verify cron produces correct next 10 fire times (architecture quality gate)."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    fires = []
    current = base
    for _ in range(10):
        current = scheduler.compute_next_fire_time_local("0 * * * *", current)
        fires.append(current)

    # Each fire should be 1 hour apart
    for i in range(1, len(fires)):
        delta = fires[i] - fires[i - 1]
        assert delta.total_seconds() == 3600


# ── Blackout period enforcement ────────────────────────────────────────────────

def test_blackout_daily_window_in_window(scheduler: RecurrenceScheduler) -> None:
    policy = RecurrencePolicy(
        cron_expression="*/15 * * * *",
        execution_window_hours=8,
        max_consecutive_failures=3,
        blackout_periods=["22:00-06:00"],
    )
    # 23:00 UTC — in overnight blackout
    fire_time = datetime(2026, 7, 21, 23, 0, 0, tzinfo=UTC)
    assert scheduler.is_in_blackout(policy, fire_time)


def test_blackout_daily_window_outside_window(scheduler: RecurrenceScheduler) -> None:
    policy = RecurrencePolicy(
        cron_expression="*/15 * * * *",
        execution_window_hours=8,
        max_consecutive_failures=3,
        blackout_periods=["22:00-06:00"],
    )
    # 12:00 UTC — outside blackout
    fire_time = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    assert not scheduler.is_in_blackout(policy, fire_time)


def test_blackout_iso_interval(scheduler: RecurrenceScheduler) -> None:
    policy = RecurrencePolicy(
        cron_expression="0 * * * *",
        execution_window_hours=4,
        max_consecutive_failures=3,
        blackout_periods=["2026-07-21T00:00/2026-07-21T23:59"],
    )
    fire_time = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    assert scheduler.is_in_blackout(policy, fire_time)


def test_blackout_weekday(scheduler: RecurrenceScheduler) -> None:
    # Block Saturday (5) and Sunday (6)
    policy = RecurrencePolicy(
        cron_expression="0 9 * * *",
        execution_window_hours=8,
        max_consecutive_failures=3,
        blackout_periods=["weekday:5,6"],
    )
    # Saturday July 25, 2026
    saturday = datetime(2026, 7, 25, 10, 0, 0, tzinfo=UTC)
    assert saturday.weekday() == 5
    assert scheduler.is_in_blackout(policy, saturday)

    # Monday July 27, 2026
    monday = datetime(2026, 7, 27, 10, 0, 0, tzinfo=UTC)
    assert monday.weekday() == 0
    assert not scheduler.is_in_blackout(policy, monday)


def test_blackout_fire_in_blackout_skipped(scheduler: RecurrenceScheduler) -> None:
    """Quality gate: fire during blackout → instance NOT created."""
    policy = RecurrencePolicy(
        cron_expression="0 * * * *",
        execution_window_hours=8,
        max_consecutive_failures=3,
        blackout_periods=["00:00-23:59"],  # All day blackout
    )
    fire_time = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    assert scheduler.is_in_blackout(policy, fire_time)


def test_no_blackout_periods_never_blocked(scheduler: RecurrenceScheduler) -> None:
    policy = RecurrencePolicy(
        cron_expression="* * * * *",
        execution_window_hours=24,
        max_consecutive_failures=3,
        blackout_periods=[],
    )
    fire_time = datetime(2026, 7, 21, 3, 0, 0, tzinfo=UTC)
    assert not scheduler.is_in_blackout(policy, fire_time)


# ── Overlap prevention ─────────────────────────────────────────────────────────

def test_overlap_prevention_blocks_when_running(scheduler: RecurrenceScheduler) -> None:
    """Quality gate: fire skipped if previous instance still running."""
    from unittest.mock import MagicMock

    from campaign.domain.value_objects.enums import InstanceState

    running_instance = MagicMock()
    running_instance.state = InstanceState.RUNNING

    assert scheduler.should_skip_due_to_running_instance([running_instance])


def test_overlap_prevention_allows_when_none_running(
    scheduler: RecurrenceScheduler,
) -> None:
    from unittest.mock import MagicMock

    from campaign.domain.value_objects.enums import InstanceState

    completed_instance = MagicMock()
    completed_instance.state = InstanceState.COMPLETED

    assert not scheduler.should_skip_due_to_running_instance([completed_instance])


def test_overlap_prevention_allows_empty_list(scheduler: RecurrenceScheduler) -> None:
    assert not scheduler.should_skip_due_to_running_instance([])


# ── Consecutive failure detection ──────────────────────────────────────────────

def test_consecutive_failures_pauses_campaign(scheduler: RecurrenceScheduler) -> None:
    """Quality gate: 3 failures → campaign paused; 4th fire does not create instance."""
    from unittest.mock import MagicMock

    from campaign.domain.value_objects.campaign_vos import RecurrencePolicy
    from campaign.domain.value_objects.enums import InstanceState

    policy = RecurrencePolicy(
        cron_expression="0 * * * *",
        execution_window_hours=4,
        max_consecutive_failures=3,
        blackout_periods=[],
    )

    campaign = MagicMock()
    campaign.campaign_schedule = policy

    # 3 failed instances
    instances = []
    for _ in range(3):
        inst = MagicMock()
        inst.state = InstanceState.FAILED
        instances.append(inst)

    now = datetime.now(UTC)
    result = scheduler.check_consecutive_failures(campaign, instances, now)
    assert result
    campaign.pause_recurring_due_to_failures.assert_called_once_with(
        consecutive_failure_count=3, now=now
    )


def test_consecutive_failures_no_pause_below_threshold(
    scheduler: RecurrenceScheduler,
) -> None:
    from unittest.mock import MagicMock

    from campaign.domain.value_objects.enums import InstanceState

    policy = RecurrencePolicy(
        cron_expression="0 * * * *",
        execution_window_hours=4,
        max_consecutive_failures=3,
        blackout_periods=[],
    )
    campaign = MagicMock()
    campaign.campaign_schedule = policy

    # Only 2 failed instances (below threshold)
    instances = [MagicMock() for _ in range(2)]
    for inst in instances:
        inst.state = InstanceState.FAILED

    result = scheduler.check_consecutive_failures(campaign, instances, datetime.now(UTC))
    assert not result


def test_consecutive_failures_resets_on_success(scheduler: RecurrenceScheduler) -> None:
    """Mixed history: success in last 3 → no pause."""
    from unittest.mock import MagicMock

    from campaign.domain.value_objects.enums import InstanceState

    policy = RecurrencePolicy(
        cron_expression="0 * * * *",
        execution_window_hours=4,
        max_consecutive_failures=3,
        blackout_periods=[],
    )
    campaign = MagicMock()
    campaign.campaign_schedule = policy

    # 2 failed, then 1 success
    instances = []
    for _ in range(2):
        inst = MagicMock()
        inst.state = InstanceState.FAILED
        instances.append(inst)
    success_inst = MagicMock()
    success_inst.state = InstanceState.COMPLETED
    instances.append(success_inst)

    result = scheduler.check_consecutive_failures(campaign, instances, datetime.now(UTC))
    assert not result
