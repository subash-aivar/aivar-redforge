"""Domain exceptions for the Feed Synchronization Foundation
sub-context — M22 Phase 2.

Two exception families, matching the exact base-class split already
established by `core.exceptions` and used throughout the codebase
(e.g. `domain/rbac/exceptions.py`):

- `ValidationError` subclasses — malformed input / configuration that
  never should have been constructed in the first place. Maps to HTTP
  422 via `ErrorHandlerMiddleware`.
- `ConflictError` subclasses — the input was well-formed, but the
  operation conflicts with the `Feed`/`FeedSyncRun`'s *current state*
  (already running, wrong lifecycle status). Maps to HTTP 409.

`NotFoundError` (feed/run lookup misses) is raised directly from
`core.exceptions` at the application layer — no domain-specific
subclass needed, mirroring how M22 Phase 1's query service does the
same for missing tactics/techniques/vulnerabilities.
"""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, ValidationError


class InvalidFeedKeyError(ValidationError):
    def __init__(self, raw: str) -> None:
        super().__init__(
            f"Invalid feed key: {raw!r} — expected lowercase snake_case, "
            "3-64 characters, starting with a letter"
        )


class InvalidSyncScheduleError(ValidationError):
    pass


class InvalidRetryPolicyError(ValidationError):
    pass


class InvalidFeedScopeError(ValidationError):
    """Raised when a `Feed`'s scope/organization_id pairing violates the
    GLOBAL-must-be-org-less / TENANT-must-carry-org invariant — the
    exact same invariant `InvalidIngestionScopeError` enforces for
    `ReferenceDataIngestionRecord` in M22 Phase 1, applied here to feed
    configuration rather than ingestion-log rows."""


class InvalidFeedStatusTransitionError(ConflictError):
    """Raised when an illegal `FeedStatus` transition is attempted
    (e.g. resuming a feed that was never paused, or any transition out
    of the terminal DISABLED state). A `ConflictError` (HTTP 409), not
    a `ValidationError`: the request itself is well-formed, it simply
    conflicts with the feed's current lifecycle state — the same
    classification `FeedNotActiveError`/`FeedSyncAlreadyRunningError`
    already use below."""

    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid feed status transition: {from_status} -> {to_status}")
        self.from_status = from_status
        self.to_status = to_status


class UnknownFeedConnectorError(ValidationError):
    """Raised when a sync is triggered for a `FeedSourceKind` that has
    no `FeedSyncExecutor` registered in the `FeedConnectorRegistry` —
    the expected, honest outcome for every feed in Phase 2, since no
    concrete connector (STIX, TAXII, or otherwise) is implemented until
    Phase 3. Distinct from a configuration error: the feed itself is
    valid, its connector simply does not exist yet."""

    def __init__(self, source_kind: str) -> None:
        super().__init__(f"No feed connector registered for source kind {source_kind!r}")


class FeedNotActiveError(ConflictError):
    """Raised when a sync is triggered for a `Feed` that is not
    currently ACTIVE (DRAFT, PAUSED, or DISABLED)."""

    def __init__(self, feed_id: str, current_status: str) -> None:
        super().__init__(
            f"Feed {feed_id} must be ACTIVE to synchronize (current: {current_status})"
        )
        self.feed_id = feed_id
        self.current_status = current_status


class FeedSyncAlreadyRunningError(ConflictError):
    """Raised when a sync is triggered for a `Feed` that already has a
    non-terminal (PENDING/RUNNING) `FeedSyncRun` — the domain-level
    idempotency guard, backed at the database layer by a partial
    unique index on `feed_sync_runs.feed_id` (see migration 0036) and
    at the process layer by a PostgreSQL advisory lock, so this is
    still correctly raised even under concurrent triggers across
    multiple application instances."""

    def __init__(self, feed_id: str) -> None:
        super().__init__(f"A sync is already running for feed {feed_id}")
        self.feed_id = feed_id


class DuplicateFeedKeyError(ConflictError):
    """Raised when registering a `Feed` whose (scope[, organization_id],
    feed_key) tuple already exists."""

    def __init__(self, feed_key: str) -> None:
        super().__init__(f"A feed with key {feed_key!r} is already registered in this scope")
