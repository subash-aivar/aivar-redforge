"""Dead Letter Queue — Sprint 26.

Stores events that failed all retry attempts so they can be:
1. Inspected by operators.
2. Requeued for retry after a fix is deployed.
3. Discarded when they are genuinely invalid.

Poison event detection:
    When the same event_id fails >= poison_threshold times, the supervisor
    considers it a poison event and routes to DLQ rather than retrying further.
    This prevents infinite retry loops that block the projection.

Design rules:
- No infrastructure imports.
- InMemoryDeadLetterQueue is the reference implementation (no DB dependency).
- Thread-safe — supervisors write from asyncio tasks.
- Multi-tenant: all list/depth operations filter by organization_id.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from redforge.application.platform.runtime_contracts import DeadLetterEntry

if TYPE_CHECKING:
    from collections.abc import Sequence


def _utc_now() -> datetime:
    return datetime.now(UTC)


class DeadLetterQueueFullError(Exception):
    """Raised when the DLQ has reached its capacity limit."""

    def __init__(self, max_size: int) -> None:
        super().__init__(f"Dead letter queue is full (max_size={max_size})")
        self.max_size = max_size


class DeadLetterEntryNotFoundError(Exception):
    """Raised when an entry_id is not found in the DLQ."""

    def __init__(self, entry_id: str) -> None:
        super().__init__(f"Dead letter entry not found: {entry_id!r}")
        self.entry_id = entry_id


class InMemoryDeadLetterQueue:
    """Thread-safe in-memory DLQ.

    Ordered insertion (FIFO per organisation). Bounded by max_size to
    prevent memory exhaustion when a projection is permanently broken.

    When full, new entries raise DeadLetterQueueFullError — this surfaces
    the operational problem rather than silently dropping entries.
    """

    def __init__(self, max_size: int = 10_000) -> None:
        self._max_size = max_size
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, DeadLetterEntry] = OrderedDict()
        self._requeued_ids: set[str] = set()
        self._inflight_ids: set[str] = set()
        self._exhausted_ids: set[str] = set()

    async def store(self, entry: DeadLetterEntry) -> None:
        with self._lock:
            if entry.entry_id in self._entries:
                return
            if len(self._entries) >= self._max_size:
                raise DeadLetterQueueFullError(self._max_size)
            self._entries[entry.entry_id] = entry

    async def list(
        self,
        organization_id: str,
        source_projection: str | None = None,
        max_count: int | None = None,
    ) -> Sequence[DeadLetterEntry]:
        with self._lock:
            results: list[DeadLetterEntry] = []
            for entry in self._entries.values():
                if entry.organization_id != organization_id:
                    continue
                if source_projection is not None and entry.source_projection != source_projection:
                    continue
                results.append(entry)
                if max_count is not None and len(results) >= max_count:
                    break
            return results

    async def requeue(self, entry_id: str) -> DeadLetterEntry:
        """Return a copy of the entry with incremented retry_count.

        Marks the entry for replay by DLQReplayWorker. The worker
        polls list_pending_replay() and calls mark_replayed() on success.
        """
        with self._lock:
            existing = self._entries.get(entry_id)
            if existing is None:
                raise DeadLetterEntryNotFoundError(entry_id)
            updated = DeadLetterEntry(
                entry_id=existing.entry_id,
                source_projection=existing.source_projection,
                event_id=existing.event_id,
                event_type=existing.event_type,
                payload=existing.payload,
                error_message=existing.error_message,
                retry_count=existing.retry_count + 1,
                first_failed_at=existing.first_failed_at,
                last_failed_at=_utc_now(),
                organization_id=existing.organization_id,
            )
            self._entries[entry_id] = updated
            self._requeued_ids.add(entry_id)
            return updated

    async def discard(self, entry_id: str) -> None:
        with self._lock:
            if entry_id not in self._entries:
                raise DeadLetterEntryNotFoundError(entry_id)
            del self._entries[entry_id]
            self._requeued_ids.discard(entry_id)

    async def depth(self, organization_id: str) -> int:
        with self._lock:
            return sum(
                1 for e in self._entries.values()
                if e.organization_id == organization_id
            )

    async def total_depth(self) -> int:
        with self._lock:
            return len(self._entries)

    async def list_pending_replay(self, max_count: int = 100) -> Sequence[DeadLetterEntry]:
        """Atomically claim entries for replay (requeued → in_flight).

        Returned entries are moved to in_flight so concurrent callers cannot
        claim the same entry. Call release_inflight() on failure or
        mark_replayed() on success.
        """
        with self._lock:
            result: list[DeadLetterEntry] = []
            for entry_id, entry in self._entries.items():
                if entry_id in self._requeued_ids:
                    result.append(entry)
                    self._requeued_ids.discard(entry_id)
                    self._inflight_ids.add(entry_id)
                    if len(result) >= max_count:
                        break
            return result

    async def mark_replayed(self, entry_id: str) -> None:
        """Remove an entry after successful replay."""
        with self._lock:
            self._entries.pop(entry_id, None)
            self._requeued_ids.discard(entry_id)
            self._inflight_ids.discard(entry_id)
            self._exhausted_ids.discard(entry_id)

    async def mark_exhausted(self, entry_id: str) -> None:
        """Move an entry to the terminal exhausted state.

        Exhausted entries remain in the queue for operator inspection
        but are never picked up for replay again.
        """
        with self._lock:
            if entry_id not in self._entries:
                return
            self._requeued_ids.discard(entry_id)
            self._inflight_ids.discard(entry_id)
            self._exhausted_ids.add(entry_id)

    async def release_inflight(self, entry_id: str) -> None:
        """Return an in-flight entry to requeued state after replay failure."""
        with self._lock:
            if entry_id not in self._entries:
                return
            self._inflight_ids.discard(entry_id)
            self._requeued_ids.add(entry_id)

    @property
    def inflight_count(self) -> int:
        """Number of entries currently in-flight."""
        with self._lock:
            return len(self._inflight_ids)

    @property
    def exhausted_count(self) -> int:
        """Number of entries in terminal exhausted state (DEBT-S31-3 accessor)."""
        with self._lock:
            return len(self._exhausted_ids)

    @property
    def requeued_count(self) -> int:
        """Number of entries pending replay."""
        with self._lock:
            return len(self._requeued_ids)

    def clear_all(self) -> int:
        """Remove all entries. Returns count removed. Test/admin use only."""
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            self._requeued_ids.clear()
            self._inflight_ids.clear()
            self._exhausted_ids.clear()
            return count


class PoisonEventDetector:
    """Tracks consecutive failures per (projection, event_id) pair.

    Used by supervisors to identify poison events — events that fail
    repeatedly regardless of retry strategy.

    Thread-safe via threading.Lock.
    """

    def __init__(self, poison_threshold: int = 3) -> None:
        self._poison_threshold = poison_threshold
        self._lock = threading.Lock()
        self._failure_counts: dict[tuple[str, str], int] = {}

    def record_failure(self, projection_name: str, event_id: str) -> int:
        """Record a failure and return the current failure count."""
        key = (projection_name, event_id)
        with self._lock:
            count = self._failure_counts.get(key, 0) + 1
            self._failure_counts[key] = count
            return count

    def is_poison(self, projection_name: str, event_id: str) -> bool:
        """Return True when failure count has reached the poison threshold."""
        key = (projection_name, event_id)
        with self._lock:
            return self._failure_counts.get(key, 0) >= self._poison_threshold

    def reset(self, projection_name: str, event_id: str) -> None:
        """Clear failure count after successful processing."""
        key = (projection_name, event_id)
        with self._lock:
            self._failure_counts.pop(key, None)

    def failure_count(self, projection_name: str, event_id: str) -> int:
        key = (projection_name, event_id)
        with self._lock:
            return self._failure_counts.get(key, 0)

    def all_poison_events(self) -> list[tuple[str, str]]:
        with self._lock:
            return [
                key for key, count in self._failure_counts.items()
                if count >= self._poison_threshold
            ]
