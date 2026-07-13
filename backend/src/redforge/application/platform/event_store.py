"""InMemoryEventStore — canonical in-process EventStore implementation.

This is NOT a production store. It is:
1. The reference implementation all projections and tests run against.
2. The specification for what any future storage implementation must honour.
3. Thread-safe for concurrent publisher tests.

Production storage (PostgreSQL, EventStoreDB, Kafka, etc.) plugs in by
implementing the EventStore protocol in src/redforge/infrastructure/.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Sequence

from redforge.domain.platform.events import EventBatch, EventEnvelope, EventSnapshot
from redforge.domain.platform.exceptions import (
    DuplicateEventError,
    MultiTenantViolationError,
    OptimisticConcurrencyError,
    StreamNotFoundError,
)
from redforge.domain.platform.value_objects import ReplayCursor


def _utc_now() -> datetime:
    return datetime.now(UTC)


class InMemoryEventStore:
    """Thread-safe, append-only in-memory EventStore.

    Indexes maintained:
    - _all: global ordered list of all envelopes
    - _by_stream: stream_id → list[EventEnvelope] (stream-ordered)
    - _by_org: org_id → list[EventEnvelope] (global-ordered)
    - _by_event_id: event_id → EventEnvelope (dedup guard)
    - _by_correlation: correlation_id → list[EventEnvelope]
    - _stream_versions: stream_id → current version (max stream_position)
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._all: list[EventEnvelope] = []
        self._by_stream: dict[str, list[EventEnvelope]] = {}
        self._by_org: dict[str, list[EventEnvelope]] = {}
        self._by_event_id: dict[str, EventEnvelope] = {}
        self._by_correlation: dict[str, list[EventEnvelope]] = {}
        self._by_event_type: dict[str, list[EventEnvelope]] = {}
        self._stream_versions: dict[str, int] = {}
        self._global_position: int = 0

    # ── Append ─────────────────────────────────────────────────────────────

    async def append(self, batch: EventBatch) -> Sequence[EventEnvelope]:
        with self._lock:
            stream_id = batch.stream_id
            org_id = batch.organization_id

            # Optimistic concurrency check
            current_version = self._stream_versions.get(stream_id, -1)
            if (
                batch.expected_stream_version is not None
                and batch.expected_stream_version != current_version
            ):
                raise OptimisticConcurrencyError(
                    stream_id=stream_id,
                    expected_version=batch.expected_stream_version,
                    actual_version=current_version,
                )

            # Dedup check
            for ev in batch.events:
                if ev.event_id in self._by_event_id:
                    raise DuplicateEventError(ev.event_id)

            stored: list[EventEnvelope] = []
            next_stream_pos = current_version + 1
            now = _utc_now()

            for ev in batch.events:
                global_pos = self._global_position
                self._global_position += 1

                stored_ev = EventEnvelope(
                    event_id=ev.event_id,
                    stream_id=ev.stream_id,
                    stream_position=next_stream_pos,
                    global_position=global_pos,
                    event_type=ev.event_type,
                    aggregate_type=ev.aggregate_type,
                    aggregate_id=ev.aggregate_id,
                    organization_id=ev.organization_id,
                    payload=ev.payload,
                    metadata=ev.metadata,
                    occurred_at=ev.occurred_at,
                    recorded_at=now,
                )
                next_stream_pos += 1

                self._all.append(stored_ev)
                self._by_event_id[stored_ev.event_id] = stored_ev

                self._by_stream.setdefault(stream_id, []).append(stored_ev)
                self._by_org.setdefault(org_id, []).append(stored_ev)

                corr = stored_ev.correlation_id
                self._by_correlation.setdefault(corr, []).append(stored_ev)

                et = stored_ev.event_type
                self._by_event_type.setdefault(et, []).append(stored_ev)

                stored.append(stored_ev)

            self._stream_versions[stream_id] = next_stream_pos - 1
            return stored

    # ── Read operations ────────────────────────────────────────────────────

    async def read_stream(
        self,
        stream_id: str,
        organization_id: str,
        from_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        with self._lock:
            events = self._by_stream.get(stream_id)
            if events is None:
                raise StreamNotFoundError(stream_id)
            # Tenant isolation
            for ev in events:
                if ev.organization_id != organization_id:
                    raise MultiTenantViolationError(organization_id, ev.organization_id)
            sliced = [e for e in events if e.stream_position >= from_position]
            if max_count is not None:
                sliced = sliced[:max_count]
            return list(sliced)

    async def read_all(
        self,
        organization_id: str,
        from_global_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        with self._lock:
            events = self._by_org.get(organization_id, [])
            sliced = [e for e in events if e.global_position >= from_global_position]
            if max_count is not None:
                sliced = sliced[:max_count]
            return list(sliced)

    async def stream_version(self, stream_id: str, organization_id: str) -> int:
        with self._lock:
            return self._stream_versions.get(stream_id, -1)

    async def event_count(self, organization_id: str) -> int:
        with self._lock:
            return len(self._by_org.get(organization_id, []))

    async def stream_ids(self, organization_id: str) -> Sequence[str]:
        with self._lock:
            org_events = self._by_org.get(organization_id, [])
            seen: set[str] = set()
            result: list[str] = []
            for ev in org_events:
                if ev.stream_id not in seen:
                    seen.add(ev.stream_id)
                    result.append(ev.stream_id)
            return result

    async def read_by_correlation_id(
        self,
        correlation_id: str,
        organization_id: str,
    ) -> Sequence[EventEnvelope]:
        with self._lock:
            events = self._by_correlation.get(correlation_id, [])
            return [e for e in events if e.organization_id == organization_id]

    async def read_by_event_type(
        self,
        event_type: str,
        organization_id: str,
        from_global_position: int = 0,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        with self._lock:
            events = self._by_event_type.get(event_type, [])
            sliced = [
                e
                for e in events
                if e.organization_id == organization_id
                and e.global_position >= from_global_position
            ]
            if max_count is not None:
                sliced = sliced[:max_count]
            return sliced

    async def read_by_time_range(
        self,
        organization_id: str,
        from_dt: object,
        to_dt: object,
        max_count: int | None = None,
    ) -> Sequence[EventEnvelope]:
        with self._lock:
            events = self._by_org.get(organization_id, [])
            sliced = [
                e
                for e in events
                if e.occurred_at >= from_dt and e.occurred_at <= to_dt  # type: ignore[operator]
            ]
            if max_count is not None:
                sliced = sliced[:max_count]
            return sliced

    async def tombstone(
        self,
        stream_id: str,
        event_id: str,
        organization_id: str,
    ) -> None:
        """GDPR right-to-erasure stub (DEBT-S26). No-op on in-memory store."""
        # In-memory store is test/dev only; no persistent PII to erase.
        # Production erasure is implemented on PostgreSQLEventStore.

    # ── AsyncIterator helpers (used by ReplayEngine) ───────────────────────

    async def iter_org(
        self,
        organization_id: str,
        from_position: int = 0,
        max_events: int | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        with self._lock:
            events = [
                e
                for e in self._by_org.get(organization_id, [])
                if e.global_position >= from_position
            ]
            if max_events is not None:
                events = events[:max_events]
        for ev in events:
            yield ev

    async def iter_stream(
        self,
        stream_id: str,
        organization_id: str,
        from_stream_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        with self._lock:
            stream = self._by_stream.get(stream_id, [])
            events = [
                e
                for e in stream
                if e.organization_id == organization_id
                and e.stream_position >= from_stream_position
            ]
        for ev in events:
            yield ev

    async def iter_aggregate(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
        from_position: int = 0,
    ) -> AsyncIterator[EventEnvelope]:
        with self._lock:
            stream_id = f"{aggregate_type}:{aggregate_id}"
            stream = self._by_stream.get(stream_id, [])
            events = [
                e
                for e in stream
                if e.organization_id == organization_id
                and e.global_position >= from_position
            ]
        for ev in events:
            yield ev

    async def iter_by_time_range(
        self,
        organization_id: str,
        from_dt: datetime,
        to_dt: datetime,
        event_types: Sequence[str] | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        with self._lock:
            events = [
                e
                for e in self._by_org.get(organization_id, [])
                if from_dt <= e.occurred_at <= to_dt
                and (event_types is None or e.event_type in event_types)
            ]
        for ev in events:
            yield ev

    async def iter_by_correlation(
        self,
        correlation_id: str,
        organization_id: str,
    ) -> AsyncIterator[EventEnvelope]:
        with self._lock:
            events = [
                e
                for e in self._by_correlation.get(correlation_id, [])
                if e.organization_id == organization_id
            ]
        for ev in events:
            yield ev

    async def iter_by_event_type(
        self,
        event_type: str,
        organization_id: str,
        from_position: int = 0,
        max_events: int | None = None,
    ) -> AsyncIterator[EventEnvelope]:
        with self._lock:
            events = [
                e
                for e in self._by_event_type.get(event_type, [])
                if e.organization_id == organization_id
                and e.global_position >= from_position
            ]
            if max_events is not None:
                events = events[:max_events]
        for ev in events:
            yield ev

    async def iter_from_cursor(
        self,
        cursor: ReplayCursor,
        organization_id: str,
        max_events: int | None = None,
    ) -> tuple[list[EventEnvelope], ReplayCursor]:
        with self._lock:
            events = [
                e
                for e in self._by_org.get(organization_id, [])
                if e.global_position >= cursor.global_position
            ]
            if max_events is not None:
                events = events[:max_events]

        if not events:
            return [], cursor.exhaust()
        next_cursor = cursor.advance(events[-1].global_position + 1)
        return events, next_cursor

    # ── Snapshot support ───────────────────────────────────────────────────

    def __len__(self) -> int:
        with self._lock:
            return len(self._all)

    def total_event_count(self) -> int:
        with self._lock:
            return len(self._all)


class InMemorySnapshotStore:
    """Thread-safe in-memory SnapshotStore."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # key: (aggregate_type, aggregate_id, org_id) → latest snapshot
        self._snapshots: dict[tuple[str, str, str], EventSnapshot] = {}
        # key: (aggregate_type, org_id) → list[snapshot]
        self._by_aggregate_type: dict[tuple[str, str], list[EventSnapshot]] = {}

    async def save_snapshot(self, snapshot: EventSnapshot) -> None:
        with self._lock:
            key = (snapshot.aggregate_type, snapshot.aggregate_id, snapshot.organization_id)
            existing = self._snapshots.get(key)
            if existing is None or snapshot.is_newer_than(existing):
                self._snapshots[key] = snapshot
            type_key = (snapshot.aggregate_type, snapshot.organization_id)
            self._by_aggregate_type.setdefault(type_key, []).append(snapshot)

    async def load_latest_snapshot(
        self,
        aggregate_type: str,
        aggregate_id: str,
        organization_id: str,
    ) -> EventSnapshot | None:
        with self._lock:
            return self._snapshots.get((aggregate_type, aggregate_id, organization_id))

    async def list_snapshots(
        self,
        aggregate_type: str,
        organization_id: str,
    ) -> Sequence[EventSnapshot]:
        with self._lock:
            return list(self._by_aggregate_type.get((aggregate_type, organization_id), []))
