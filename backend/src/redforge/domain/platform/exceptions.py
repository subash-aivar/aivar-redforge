"""Platform domain exceptions — Sprint 24."""

from __future__ import annotations


class PlatformError(Exception):
    """Root exception for the Platform bounded context."""


class EventStoreError(PlatformError):
    """Raised for event store operation failures."""


class StreamNotFoundError(EventStoreError):
    """Raised when reading a stream that does not exist."""

    def __init__(self, stream_id: str) -> None:
        super().__init__(f"Stream not found: {stream_id!r}")
        self.stream_id = stream_id


class OptimisticConcurrencyError(EventStoreError):
    """Raised when an append fails due to stream version mismatch.

    Indicates a concurrent writer appended to the stream between the caller's
    last read and this write attempt.
    """

    def __init__(
        self,
        stream_id: str,
        expected_version: int,
        actual_version: int,
    ) -> None:
        super().__init__(
            f"Optimistic concurrency conflict on stream {stream_id!r}: "
            f"expected version {expected_version}, got {actual_version}"
        )
        self.stream_id = stream_id
        self.expected_version = expected_version
        self.actual_version = actual_version


class DuplicateEventError(EventStoreError):
    """Raised when an event_id already exists in the store.

    The EventStore is idempotent on event_id: re-appending the same event_id
    raises this error rather than silently duplicating.
    """

    def __init__(self, event_id: str) -> None:
        super().__init__(f"Duplicate event_id: {event_id!r}")
        self.event_id = event_id


class ProjectionError(PlatformError):
    """Raised when a projection fails to process an event."""

    def __init__(self, projection_name: str, event_id: str, cause: str) -> None:
        super().__init__(
            f"Projection {projection_name!r} failed on event {event_id!r}: {cause}"
        )
        self.projection_name = projection_name
        self.event_id = event_id


class CheckpointError(PlatformError):
    """Raised when checkpoint save/load fails."""


class SnapshotError(PlatformError):
    """Raised when snapshot serialisation or deserialisation fails."""


class ReplayError(PlatformError):
    """Raised when a replay operation fails."""


class MultiTenantViolationError(PlatformError):
    """Raised when an operation would cross organisation boundaries.

    The platform enforces strict tenant isolation: no query, projection, or
    replay may return events from a different organisation_id than requested.
    """

    def __init__(self, expected_org: str, actual_org: str) -> None:
        super().__init__(
            f"Multi-tenant violation: expected org {expected_org!r}, "
            f"got org {actual_org!r}"
        )
        self.expected_org = expected_org
        self.actual_org = actual_org


class ReadModelNotFoundError(PlatformError):
    """Raised when a read model cannot be found in the repository."""

    def __init__(self, model_type: str, organization_id: str) -> None:
        super().__init__(
            f"ReadModel {model_type!r} not found for org {organization_id!r}"
        )
        self.model_type = model_type
        self.organization_id = organization_id
