"""M22 Phase 2 — Feed Synchronization Foundation domain unit tests.

Pure-function, no I/O, no database. Covers:
  - Value objects: FeedKey, SyncSchedule (minimum interval floor),
    RetryPolicy (validation mirroring RetryConfig)
  - Enums: FeedSourceKind, FeedStatus, FeedSyncRunStatus, FeedSyncTrigger
  - Aggregate: Feed (registration, scope invariant, lifecycle
    transitions, configuration updates, sync bookkeeping, domain events)
  - Aggregate: FeedSyncRun (start/finalize lifecycle, domain events)
  - Domain exceptions
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime

import pytest

from redforge.domain.threat_intel.feed_entity import Feed
from redforge.domain.threat_intel.feed_events import (
    FeedActivated,
    FeedDisabled,
    FeedPaused,
    FeedRegistered,
    FeedSyncRunFailed,
    FeedSyncRunStarted,
    FeedSyncRunSucceeded,
)
from redforge.domain.threat_intel.feed_exceptions import (
    DuplicateFeedKeyError,
    FeedNotActiveError,
    FeedSyncAlreadyRunningError,
    InvalidFeedKeyError,
    InvalidFeedStatusTransitionError,
    InvalidRetryPolicyError,
    InvalidSyncScheduleError,
    UnknownFeedConnectorError,
)
from redforge.domain.threat_intel.feed_sync_run_entity import (
    FeedSyncRun,
    FeedSyncRunAlreadyFinalizedError,
)
from redforge.domain.threat_intel.feed_value_objects import (
    MIN_SYNC_INTERVAL_SECONDS,
    FeedKey,
    FeedSourceKind,
    FeedStatus,
    FeedSyncRunStatus,
    FeedSyncTrigger,
    RetryPolicy,
    SyncSchedule,
)
from redforge.domain.threat_intel.reference_data_exceptions import InvalidIngestionScopeError
from redforge.domain.threat_intel.reference_data_value_objects import IngestionScope

_NOW = datetime(2026, 7, 1, tzinfo=UTC)


# ─── FeedKey ─────────────────────────────────────────────────────────────────


class TestFeedKey:
    @pytest.mark.parametrize(
        "raw", ["mitre_attack_enterprise", "cisa_kev", "abc", "a" * 64]
    )
    def test_accepts_valid_keys(self, raw: str) -> None:
        assert FeedKey(raw).value == raw

    @pytest.mark.parametrize(
        "raw",
        ["", "ab", "A_TEST", "Mitre_Attack", "1feed", "feed-key", "feed key", "a" * 65],
    )
    def test_rejects_invalid_keys(self, raw: str) -> None:
        with pytest.raises(InvalidFeedKeyError):
            FeedKey(raw)

    def test_str_returns_raw_value(self) -> None:
        assert str(FeedKey("cisa_kev")) == "cisa_kev"

    def test_is_frozen(self) -> None:
        key = FeedKey("cisa_kev")
        with pytest.raises(dataclasses.FrozenInstanceError):
            key.value = "other"  # type: ignore[misc]


# ─── SyncSchedule ────────────────────────────────────────────────────────────


class TestSyncSchedule:
    def test_accepts_minimum_interval(self) -> None:
        schedule = SyncSchedule(interval_seconds=MIN_SYNC_INTERVAL_SECONDS)
        assert schedule.interval_seconds == MIN_SYNC_INTERVAL_SECONDS

    def test_accepts_larger_interval(self) -> None:
        schedule = SyncSchedule(interval_seconds=86400)
        assert schedule.interval_seconds == 86400

    @pytest.mark.parametrize("interval", [0, 1, 60, 299, -100])
    def test_rejects_below_minimum_interval(self, interval: int) -> None:
        with pytest.raises(InvalidSyncScheduleError):
            SyncSchedule(interval_seconds=interval)


# ─── RetryPolicy ─────────────────────────────────────────────────────────────


class TestRetryPolicy:
    def test_defaults_are_valid(self) -> None:
        policy = RetryPolicy()
        assert policy.max_attempts == 3
        assert policy.base_delay_seconds == 1.0
        assert policy.max_delay_seconds == 30.0
        assert policy.jitter_factor == 0.25

    def test_rejects_max_attempts_below_one(self) -> None:
        with pytest.raises(InvalidRetryPolicyError):
            RetryPolicy(max_attempts=0)

    def test_rejects_negative_base_delay(self) -> None:
        with pytest.raises(InvalidRetryPolicyError):
            RetryPolicy(base_delay_seconds=-1.0)

    def test_rejects_max_delay_below_base_delay(self) -> None:
        with pytest.raises(InvalidRetryPolicyError):
            RetryPolicy(base_delay_seconds=10.0, max_delay_seconds=5.0)

    @pytest.mark.parametrize("jitter", [-0.1, 1.1])
    def test_rejects_out_of_range_jitter(self, jitter: float) -> None:
        with pytest.raises(InvalidRetryPolicyError):
            RetryPolicy(jitter_factor=jitter)


# ─── Enums ──────────────────────────────────────────────────────────────────


class TestEnums:
    def test_feed_source_kind_is_str_subclass(self) -> None:
        assert isinstance(FeedSourceKind.STIX_TAXII_PULL, str)
        assert FeedSourceKind.STATIC_HTTP_DOWNLOAD == "static_http_download"

    def test_feed_status_values(self) -> None:
        assert FeedStatus.DRAFT == "draft"
        assert FeedStatus.ACTIVE == "active"
        assert FeedStatus.PAUSED == "paused"
        assert FeedStatus.DISABLED == "disabled"

    def test_feed_sync_run_status_values(self) -> None:
        assert FeedSyncRunStatus.PENDING == "pending"
        assert FeedSyncRunStatus.RUNNING == "running"
        assert FeedSyncRunStatus.SUCCEEDED == "succeeded"
        assert FeedSyncRunStatus.FAILED == "failed"

    def test_feed_sync_trigger_values(self) -> None:
        assert FeedSyncTrigger.SCHEDULED == "scheduled"
        assert FeedSyncTrigger.MANUAL == "manual"


# ─── Feed aggregate: registration + scope invariant ─────────────────────────


def _register(
    *,
    feed_key: str = "cisa_kev",
    scope: IngestionScope = IngestionScope.GLOBAL,
    organization_id: str | None = None,
    interval_seconds: int = MIN_SYNC_INTERVAL_SECONDS,
) -> Feed:
    return Feed.register(
        id="feed-1",
        feed_key=FeedKey(feed_key),
        display_name="CISA Known Exploited Vulnerabilities",
        source_kind=FeedSourceKind.STATIC_HTTP_DOWNLOAD,
        schedule=SyncSchedule(interval_seconds=interval_seconds),
        actor_id="admin-1",
        scope=scope,
        organization_id=organization_id,
        now=_NOW,
    )


class TestFeedRegistration:
    def test_register_starts_in_draft(self) -> None:
        feed = _register()
        assert feed.status is FeedStatus.DRAFT
        assert feed.is_syncable is False
        assert feed.checkpoint is None
        assert feed.consecutive_failure_count == 0
        assert feed.next_sync_due_at is None
        assert feed.created_by == "admin-1"
        assert feed.updated_by == "admin-1"

    def test_register_emits_domain_event(self) -> None:
        feed = _register()
        events = feed.collect_events()
        assert len(events) == 1
        event = events[0]
        assert isinstance(event, FeedRegistered)
        assert event.feed_id == "feed-1"
        assert event.feed_key == "cisa_kev"
        assert event.scope == "GLOBAL"
        assert event.organization_id is None

    def test_collect_events_drains_and_clears(self) -> None:
        feed = _register()
        first = feed.collect_events()
        second = feed.collect_events()
        assert len(first) == 1
        assert second == []

    def test_default_retry_policy_applied_when_not_supplied(self) -> None:
        feed = _register()
        assert feed.retry_policy == RetryPolicy()

    def test_global_scope_with_organization_id_raises(self) -> None:
        with pytest.raises(InvalidIngestionScopeError):
            _register(scope=IngestionScope.GLOBAL, organization_id="org-1")

    def test_tenant_scope_without_organization_id_raises(self) -> None:
        with pytest.raises(InvalidIngestionScopeError):
            _register(scope=IngestionScope.TENANT, organization_id=None)

    def test_tenant_scope_with_organization_id_is_valid(self) -> None:
        feed = _register(scope=IngestionScope.TENANT, organization_id="org-1")
        assert feed.scope is IngestionScope.TENANT
        assert feed.organization_id == "org-1"


# ─── Feed aggregate: lifecycle transitions ──────────────────────────────────


class TestFeedLifecycle:
    def test_activate_from_draft(self) -> None:
        feed = _register()
        feed.collect_events()
        feed.activate(actor_id="admin-1", now=_NOW)
        assert feed.status is FeedStatus.ACTIVE
        assert feed.is_syncable is True
        assert feed.next_sync_due_at == _NOW
        events = feed.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], FeedActivated)

    def test_activate_twice_raises(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        with pytest.raises(InvalidFeedStatusTransitionError):
            feed.activate(actor_id="admin-1", now=_NOW)

    def test_pause_from_active(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.collect_events()
        feed.pause(actor_id="admin-1", now=_NOW)
        assert feed.status is FeedStatus.PAUSED
        assert feed.is_syncable is False
        assert feed.next_sync_due_at is None
        events = feed.collect_events()
        assert isinstance(events[0], FeedPaused)

    def test_pause_from_draft_raises(self) -> None:
        feed = _register()
        with pytest.raises(InvalidFeedStatusTransitionError):
            feed.pause(actor_id="admin-1")

    def test_resume_from_paused_reactivates(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.pause(actor_id="admin-1", now=_NOW)
        feed.activate(actor_id="admin-1", now=_NOW)
        assert feed.status is FeedStatus.ACTIVE
        assert feed.next_sync_due_at == _NOW

    def test_disable_from_any_non_disabled_status(self) -> None:
        feed = _register()
        feed.collect_events()
        feed.disable(actor_id="admin-1", now=_NOW)
        assert feed.status is FeedStatus.DISABLED
        assert feed.is_syncable is False
        events = feed.collect_events()
        assert isinstance(events[0], FeedDisabled)

    def test_disable_is_terminal(self) -> None:
        feed = _register()
        feed.disable(actor_id="admin-1")
        with pytest.raises(InvalidFeedStatusTransitionError):
            feed.disable(actor_id="admin-1")
        with pytest.raises(InvalidFeedStatusTransitionError):
            feed.activate(actor_id="admin-1")
        with pytest.raises(InvalidFeedStatusTransitionError):
            feed.pause(actor_id="admin-1")

    def test_is_due_false_when_not_active(self) -> None:
        feed = _register()
        assert feed.is_due(now=_NOW) is False

    def test_is_due_true_once_due_time_arrives(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        assert feed.is_due(now=_NOW) is True
        past = datetime(2026, 6, 1, tzinfo=UTC)
        assert feed.is_due(now=past) is False


# ─── Feed aggregate: configuration updates ──────────────────────────────────


class TestFeedConfigurationUpdate:
    def test_update_display_name_only(self) -> None:
        feed = _register()
        feed.update_configuration(actor_id="admin-2", display_name="Renamed Feed", now=_NOW)
        assert feed.display_name == "Renamed Feed"
        assert feed.updated_by == "admin-2"
        assert feed.status is FeedStatus.DRAFT  # untouched

    def test_update_schedule(self) -> None:
        feed = _register()
        new_schedule = SyncSchedule(interval_seconds=3600)
        feed.update_configuration(actor_id="admin-1", schedule=new_schedule)
        assert feed.schedule.interval_seconds == 3600

    def test_update_retry_policy(self) -> None:
        feed = _register()
        new_policy = RetryPolicy(max_attempts=5)
        feed.update_configuration(actor_id="admin-1", retry_policy=new_policy)
        assert feed.retry_policy.max_attempts == 5

    def test_update_connector_config_replaces_dict(self) -> None:
        feed = _register()
        feed.update_configuration(actor_id="admin-1", connector_config={"url": "https://x"})
        assert feed.connector_config == {"url": "https://x"}

    def test_connector_config_is_defensively_copied(self) -> None:
        feed = Feed.register(
            id="feed-2",
            feed_key=FeedKey("test_feed"),
            display_name="Test",
            source_kind=FeedSourceKind.MANUAL_UPLOAD,
            schedule=SyncSchedule(interval_seconds=MIN_SYNC_INTERVAL_SECONDS),
            actor_id="admin-1",
            connector_config={"a": 1},
        )
        config = feed.connector_config
        config["a"] = 999
        assert feed.connector_config == {"a": 1}


# ─── Feed aggregate: sync bookkeeping ───────────────────────────────────────


class TestFeedSyncBookkeeping:
    def test_record_sync_started_requires_active(self) -> None:
        feed = _register()
        with pytest.raises(FeedNotActiveError):
            feed.record_sync_started()

    def test_record_sync_started_sets_running(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.record_sync_started(now=_NOW)
        assert feed.last_sync_status is FeedSyncRunStatus.RUNNING
        assert feed.last_sync_started_at == _NOW

    def test_record_sync_succeeded_advances_checkpoint_and_schedule(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.record_sync_started(now=_NOW)
        feed.record_sync_succeeded(checkpoint="cursor-123", now=_NOW)
        assert feed.checkpoint == "cursor-123"
        assert feed.consecutive_failure_count == 0
        assert feed.last_sync_status is FeedSyncRunStatus.SUCCEEDED
        assert feed.next_sync_due_at is not None
        assert feed.next_sync_due_at > _NOW

    def test_record_sync_succeeded_resets_failure_count(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.record_sync_failed(now=_NOW)
        feed.record_sync_failed(now=_NOW)
        assert feed.consecutive_failure_count == 2
        feed.record_sync_succeeded(checkpoint=None, now=_NOW)
        assert feed.consecutive_failure_count == 0

    def test_record_sync_failed_increments_failure_count(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.record_sync_failed(now=_NOW)
        assert feed.consecutive_failure_count == 1
        assert feed.last_sync_status is FeedSyncRunStatus.FAILED
        assert feed.next_sync_due_at is not None

    def test_record_sync_failed_does_not_reschedule_if_no_longer_active(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.pause(actor_id="admin-1", now=_NOW)
        feed.record_sync_failed(now=_NOW)
        assert feed.next_sync_due_at is None

    def test_record_sync_succeeded_preserves_checkpoint_when_none_supplied(self) -> None:
        feed = _register()
        feed.activate(actor_id="admin-1", now=_NOW)
        feed.record_sync_succeeded(checkpoint="cursor-1", now=_NOW)
        feed.record_sync_succeeded(checkpoint=None, now=_NOW)
        assert feed.checkpoint == "cursor-1"


# ─── FeedSyncRun aggregate ──────────────────────────────────────────────────


class TestFeedSyncRun:
    def test_start_sets_running_status(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.MANUAL,
            checkpoint_before=None,
            created_by="admin-1",
            now=_NOW,
        )
        assert run.status is FeedSyncRunStatus.RUNNING
        assert run.trigger is FeedSyncTrigger.MANUAL
        assert run.started_at == _NOW
        assert run.finished_at is None

    def test_start_emits_domain_event(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.SCHEDULED,
            checkpoint_before="cursor-0",
            created_by="system",
            now=_NOW,
        )
        events = run.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], FeedSyncRunStarted)
        assert events[0].trigger == "scheduled"

    def test_mark_succeeded_transitions_and_records_metrics(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.MANUAL,
            checkpoint_before=None,
            created_by="admin-1",
            now=_NOW,
        )
        run.collect_events()
        run.mark_succeeded(
            checkpoint_after="cursor-1",
            items_fetched=10,
            items_processed=9,
            items_failed=1,
            retry_attempts_used=1,
            now=_NOW,
        )
        assert run.status is FeedSyncRunStatus.SUCCEEDED
        assert run.checkpoint_after == "cursor-1"
        assert run.items_fetched == 10
        assert run.items_processed == 9
        assert run.items_failed == 1
        assert run.finished_at == _NOW
        events = run.collect_events()
        assert isinstance(events[0], FeedSyncRunSucceeded)

    def test_mark_failed_transitions_and_records_error(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.MANUAL,
            checkpoint_before=None,
            created_by="admin-1",
            now=_NOW,
        )
        run.collect_events()
        run.mark_failed(
            error_message="connector timeout",
            retry_attempts_used=3,
            now=_NOW,
        )
        assert run.status is FeedSyncRunStatus.FAILED
        assert run.error_message == "connector timeout"
        assert run.retry_attempts_used == 3
        assert run.checkpoint_after is None
        events = run.collect_events()
        assert isinstance(events[0], FeedSyncRunFailed)

    def test_mark_succeeded_twice_raises(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.MANUAL,
            checkpoint_before=None,
            created_by="admin-1",
        )
        run.mark_succeeded(
            checkpoint_after=None,
            items_fetched=0,
            items_processed=0,
            items_failed=0,
            retry_attempts_used=0,
        )
        with pytest.raises(FeedSyncRunAlreadyFinalizedError):
            run.mark_succeeded(
                checkpoint_after=None,
                items_fetched=0,
                items_processed=0,
                items_failed=0,
                retry_attempts_used=0,
            )

    def test_mark_failed_after_succeeded_raises(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.MANUAL,
            checkpoint_before=None,
            created_by="admin-1",
        )
        run.mark_succeeded(
            checkpoint_after=None,
            items_fetched=0,
            items_processed=0,
            items_failed=0,
            retry_attempts_used=0,
        )
        with pytest.raises(FeedSyncRunAlreadyFinalizedError):
            run.mark_failed(error_message="too late", retry_attempts_used=0)

    def test_is_terminal(self) -> None:
        run = FeedSyncRun.start(
            id="run-1",
            feed_id="feed-1",
            trigger=FeedSyncTrigger.MANUAL,
            checkpoint_before=None,
            created_by="admin-1",
        )
        assert run.is_terminal is False
        run.mark_failed(error_message="boom", retry_attempts_used=1)
        assert run.is_terminal is True


# ─── Domain exceptions ───────────────────────────────────────────────────────


class TestDomainExceptions:
    def test_feed_not_active_error_message(self) -> None:
        exc = FeedNotActiveError("feed-1", "draft")
        assert "feed-1" in str(exc)
        assert "draft" in str(exc)

    def test_feed_sync_already_running_error_message(self) -> None:
        exc = FeedSyncAlreadyRunningError("feed-1")
        assert "feed-1" in str(exc)

    def test_duplicate_feed_key_error_message(self) -> None:
        exc = DuplicateFeedKeyError("cisa_kev")
        assert "cisa_kev" in str(exc)

    def test_unknown_feed_connector_error_message(self) -> None:
        exc = UnknownFeedConnectorError("stix_taxii_pull")
        assert "stix_taxii_pull" in str(exc)

    def test_invalid_feed_status_transition_error_carries_states(self) -> None:
        exc = InvalidFeedStatusTransitionError("disabled", "active")
        assert exc.from_status == "disabled"
        assert exc.to_status == "active"
