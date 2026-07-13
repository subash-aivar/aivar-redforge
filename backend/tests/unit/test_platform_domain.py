"""Unit tests for Platform domain layer — Sprint 24.

Tests: value objects, EventEnvelope, EventBatch, EventStream,
EventSnapshot, PlatformEvents, exceptions.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.domain.platform.events import (
    EventBatch,
    EventEnvelope,
    EventSnapshot,
    EventStream,
    ProjectionCaughtUp,
    ProjectionFailed,
    ReplayCompleted,
    ReplayStarted,
    SnapshotCreated,
    make_envelope,
)
from redforge.domain.platform.exceptions import (
    DuplicateEventError,
    MultiTenantViolationError,
    OptimisticConcurrencyError,
    ProjectionError,
    ReadModelNotFoundError,
    StreamNotFoundError,
)
from redforge.domain.platform.value_objects import (
    CausationId,
    CorrelationId,
    EventMetadata,
    EventVersion,
    ProjectionCheckpoint,
    ProjectionState,
    ReplayCursor,
    RetentionCategory,
    RetentionPolicy,
)

_ORG = "01KX3FWDMBVJTKGWNE273CN45D"
_NOW = datetime.now(UTC)


# ── CorrelationId ──────────────────────────────────────────────────────────

class TestCorrelationId:
    def test_generate_produces_unique_ids(self) -> None:
        a = CorrelationId.generate()
        b = CorrelationId.generate()
        assert a.value != b.value

    def test_from_string(self) -> None:
        cid = CorrelationId.from_string("abc-123")
        assert str(cid) == "abc-123"

    def test_from_string_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            CorrelationId.from_string("")

    def test_from_string_whitespace_raises(self) -> None:
        with pytest.raises(ValueError):
            CorrelationId.from_string("   ")

    def test_equality(self) -> None:
        a = CorrelationId.from_string("same")
        b = CorrelationId.from_string("same")
        assert a == b

    def test_frozen(self) -> None:
        cid = CorrelationId.from_string("x")
        with pytest.raises((AttributeError, TypeError)):
            cid.value = "y"  # type: ignore[misc]


# ── CausationId ────────────────────────────────────────────────────────────

class TestCausationId:
    def test_from_string(self) -> None:
        cid = CausationId.from_string("event-id-123")
        assert str(cid) == "event-id-123"

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            CausationId.from_string("")


# ── EventVersion ───────────────────────────────────────────────────────────

class TestEventVersion:
    def test_v1(self) -> None:
        v = EventVersion.v1()
        assert v.major == 1 and v.minor == 0

    def test_str(self) -> None:
        assert str(EventVersion.v1()) == "1.0"

    def test_compatible_same_major(self) -> None:
        assert EventVersion(1, 0).is_compatible_with(EventVersion(1, 5))

    def test_incompatible_different_major(self) -> None:
        assert not EventVersion(1, 0).is_compatible_with(EventVersion(2, 0))

    def test_from_string(self) -> None:
        v = EventVersion.from_string("2.3")
        assert v.major == 2 and v.minor == 3

    def test_from_string_invalid(self) -> None:
        with pytest.raises(ValueError):
            EventVersion.from_string("bad")


# ── EventMetadata ──────────────────────────────────────────────────────────

class TestEventMetadata:
    def _make(self) -> EventMetadata:
        return EventMetadata(correlation_id=CorrelationId.from_string("c1"))

    def test_get_custom_missing(self) -> None:
        assert self._make().get_custom("key") is None

    def test_with_custom(self) -> None:
        m = self._make().with_custom("tenant", "acme")
        assert m.get_custom("tenant") == "acme"

    def test_with_custom_immutable(self) -> None:
        m1 = self._make()
        m2 = m1.with_custom("k", "v")
        assert m1.get_custom("k") is None
        assert m2.get_custom("k") == "v"

    def test_defaults(self) -> None:
        m = self._make()
        assert m.causation_id is None
        assert m.actor_id is None
        assert m.source_service == "redforge"


# ── RetentionPolicy ────────────────────────────────────────────────────────

class TestRetentionPolicy:
    def test_default(self) -> None:
        p = RetentionPolicy.default()
        assert p.retain_days == 365

    def test_compliance(self) -> None:
        p = RetentionPolicy.compliance()
        assert p.retain_days == 2555
        assert p.archive_after_days == 365

    def test_short_lived(self) -> None:
        p = RetentionPolicy.short_lived()
        assert p.retain_days == 30
        assert p.category == RetentionCategory.HOT

    def test_invalid_retain_days(self) -> None:
        with pytest.raises(ValueError):
            RetentionPolicy(retain_days=0)

    def test_invalid_archive_days(self) -> None:
        with pytest.raises(ValueError):
            RetentionPolicy(retain_days=365, archive_after_days=0)


# ── ProjectionCheckpoint ───────────────────────────────────────────────────

class TestProjectionCheckpoint:
    def _make(self) -> ProjectionCheckpoint:
        return ProjectionCheckpoint(
            projection_id="p1",
            projection_name="test_proj",
            last_global_position=10,
            last_processed_at=_NOW,
        )

    def test_advance(self) -> None:
        cp = self._make().advance(20, _NOW)
        assert cp.last_global_position == 20
        assert cp.events_processed == 1

    def test_mark_error(self) -> None:
        cp = self._make().mark_error("boom")
        assert cp.state == ProjectionState.ERROR
        assert cp.error_message == "boom"

    def test_advance_increments_events_processed(self) -> None:
        cp = self._make().advance(11, _NOW).advance(12, _NOW)
        assert cp.events_processed == 2


# ── ReplayCursor ───────────────────────────────────────────────────────────

class TestReplayCursor:
    def test_beginning(self) -> None:
        c = ReplayCursor.beginning()
        assert c.global_position == 0
        assert not c.is_exhausted

    def test_from_position(self) -> None:
        c = ReplayCursor.from_position(100)
        assert c.global_position == 100

    def test_negative_raises(self) -> None:
        with pytest.raises(ValueError):
            ReplayCursor.from_position(-1)

    def test_advance(self) -> None:
        c = ReplayCursor.beginning().advance(50)
        assert c.global_position == 50
        assert not c.is_exhausted

    def test_exhaust(self) -> None:
        c = ReplayCursor.from_position(99).exhaust()
        assert c.is_exhausted
        assert c.global_position == 99


# ── EventEnvelope ──────────────────────────────────────────────────────────

class TestEventEnvelope:
    def _make(self, **kw: object) -> EventEnvelope:
        defaults = dict(
            event_id="evt-1",
            stream_id="campaign:agg-1",
            stream_position=0,
            global_position=0,
            event_type="campaign.CampaignCreated",
            aggregate_type="Campaign",
            aggregate_id="agg-1",
            organization_id=_ORG,
            payload={"name": "test"},
            metadata=EventMetadata(correlation_id=CorrelationId.from_string("c1")),
            occurred_at=_NOW,
            recorded_at=_NOW,
        )
        defaults.update(kw)  # type: ignore[arg-type]
        return EventEnvelope(**defaults)  # type: ignore[arg-type]

    def test_correlation_id_property(self) -> None:
        ev = self._make()
        assert ev.correlation_id == "c1"

    def test_causation_id_none(self) -> None:
        ev = self._make()
        assert ev.causation_id is None

    def test_causation_id_present(self) -> None:
        meta = EventMetadata(
            correlation_id=CorrelationId.from_string("c1"),
            causation_id=CausationId.from_string("parent-event"),
        )
        ev = self._make(metadata=meta)
        assert ev.causation_id == "parent-event"

    def test_ordering(self) -> None:
        a = self._make(global_position=0)
        b = self._make(global_position=1)
        assert a < b

    def test_with_metadata(self) -> None:
        ev = self._make()
        ev2 = ev.with_metadata("region", "us-east-1")
        assert ev2.metadata.get_custom("region") == "us-east-1"
        assert ev.metadata.get_custom("region") is None

    def test_frozen(self) -> None:
        ev = self._make()
        with pytest.raises((AttributeError, TypeError)):
            ev.event_type = "other"  # type: ignore[misc]


# ── make_envelope ──────────────────────────────────────────────────────────

class TestMakeEnvelope:
    def test_creates_valid_envelope(self) -> None:
        ev = make_envelope(
            payload={"x": 1},
            event_type="test.TestEvent",
            aggregate_type="Test",
            aggregate_id="agg-1",
            stream_id="test:agg-1",
            organization_id=_ORG,
        )
        assert ev.event_type == "test.TestEvent"
        assert ev.stream_position == 0
        assert ev.global_position == 0

    def test_auto_correlation_id(self) -> None:
        ev = make_envelope(
            payload={},
            event_type="x.Y",
            aggregate_type="X",
            aggregate_id="a",
            stream_id="x:a",
            organization_id=_ORG,
        )
        assert ev.correlation_id != ""

    def test_explicit_correlation_id(self) -> None:
        ev = make_envelope(
            payload={},
            event_type="x.Y",
            aggregate_type="X",
            aggregate_id="a",
            stream_id="x:a",
            organization_id=_ORG,
            correlation_id="my-corr-id",
        )
        assert ev.correlation_id == "my-corr-id"

    def test_causation_id_set(self) -> None:
        ev = make_envelope(
            payload={},
            event_type="x.Y",
            aggregate_type="X",
            aggregate_id="a",
            stream_id="x:a",
            organization_id=_ORG,
            causation_id="parent-evt",
        )
        assert ev.causation_id == "parent-evt"


# ── EventBatch ────────────────────────────────────────────────────────────

class TestEventBatch:
    def _env(self, stream_id: str, org: str = _ORG) -> EventEnvelope:
        return make_envelope(
            payload={},
            event_type="test.T",
            aggregate_type="T",
            aggregate_id="a",
            stream_id=stream_id,
            organization_id=org,
        )

    def test_valid_batch(self) -> None:
        ev = self._env("campaign:a")
        batch = EventBatch(stream_id="campaign:a", organization_id=_ORG, events=(ev,))
        assert len(batch.events) == 1

    def test_empty_batch_raises(self) -> None:
        with pytest.raises(ValueError):
            EventBatch(stream_id="x", organization_id=_ORG, events=())

    def test_stream_id_mismatch_raises(self) -> None:
        ev = self._env("other:stream")
        with pytest.raises(ValueError, match="stream_id mismatch"):
            EventBatch(stream_id="campaign:a", organization_id=_ORG, events=(ev,))

    def test_org_mismatch_raises(self) -> None:
        ev = self._env("campaign:a", org="other-org")
        with pytest.raises(ValueError, match="organization_id mismatch"):
            EventBatch(stream_id="campaign:a", organization_id=_ORG, events=(ev,))


# ── EventStream ────────────────────────────────────────────────────────────

class TestEventStream:
    def test_empty_stream(self) -> None:
        s = EventStream.empty("x", _ORG)
        assert s.is_empty
        assert s.version == -1

    def test_from_envelopes(self) -> None:
        ev = make_envelope(
            payload={},
            event_type="t.T",
            aggregate_type="T",
            aggregate_id="a",
            stream_id="t:a",
            organization_id=_ORG,
        )
        import dataclasses
        # Simulate stored positions
        stored = dataclasses.replace(ev, stream_position=0)
        s = EventStream.from_envelopes("t:a", _ORG, [stored])
        assert not s.is_empty
        assert s.version == 0
        assert len(s.events) == 1


# ── EventSnapshot ──────────────────────────────────────────────────────────

class TestEventSnapshot:
    def _make(self, pos: int) -> EventSnapshot:
        return EventSnapshot(
            snapshot_id="snap-1",
            aggregate_type="Campaign",
            aggregate_id="agg-1",
            organization_id=_ORG,
            state={"status": "running"},
            stream_version_at_snapshot=10,
            global_position_at_snapshot=pos,
            created_at=_NOW,
        )

    def test_is_newer_than(self) -> None:
        newer = self._make(100)
        older = self._make(50)
        assert newer.is_newer_than(older)
        assert not older.is_newer_than(newer)


# ── PlatformEvents ─────────────────────────────────────────────────────────

class TestPlatformEvents:
    def test_projection_failed_event_type(self) -> None:
        ev = ProjectionFailed(projection_id="p1", projection_name="test", error_message="boom")
        assert ev.event_type == "platform.ProjectionFailed"

    def test_projection_caught_up(self) -> None:
        ev = ProjectionCaughtUp(projection_id="p1", projection_name="test", events_replayed=100)
        assert ev.event_type == "platform.ProjectionCaughtUp"
        assert ev.events_replayed == 100

    def test_snapshot_created(self) -> None:
        ev = SnapshotCreated(aggregate_type="Campaign", aggregate_id="a1")
        assert ev.event_type == "platform.SnapshotCreated"

    def test_replay_events(self) -> None:
        started = ReplayStarted(replay_id="r1", filter_description="by org")
        completed = ReplayCompleted(replay_id="r1", events_replayed=500)
        assert started.replay_id == "r1"
        assert completed.events_replayed == 500


# ── Exceptions ────────────────────────────────────────────────────────────

class TestExceptions:
    def test_stream_not_found(self) -> None:
        exc = StreamNotFoundError("my-stream")
        assert "my-stream" in str(exc)
        assert exc.stream_id == "my-stream"

    def test_optimistic_concurrency(self) -> None:
        exc = OptimisticConcurrencyError("s1", expected_version=5, actual_version=7)
        assert exc.expected_version == 5
        assert exc.actual_version == 7
        assert "s1" in str(exc)

    def test_duplicate_event(self) -> None:
        exc = DuplicateEventError("evt-123")
        assert exc.event_id == "evt-123"

    def test_projection_error(self) -> None:
        exc = ProjectionError("my_proj", "evt-1", "null ref")
        assert exc.projection_name == "my_proj"

    def test_multi_tenant_violation(self) -> None:
        exc = MultiTenantViolationError("org-a", "org-b")
        assert "org-a" in str(exc)

    def test_read_model_not_found(self) -> None:
        exc = ReadModelNotFoundError("campaign", _ORG)
        assert "campaign" in str(exc)
