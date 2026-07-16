"""Feed connector seam — M22 Phase 2 (Feed Synchronization Foundation).

This module is the *entire* plug-in point a Phase 3 provider connector
(MITRE ATT&CK STIX bundle, CISA KEV JSON, EPSS CSV, NVD incremental
API, per-tenant STIX/TAXII pulls) needs to implement:

1. Implement `FeedSyncExecutor.execute()` for one `FeedSourceKind`.
2. Register an instance against that `FeedSourceKind` in a
   `FeedConnectorRegistry`.

`FeedSyncOrchestrationService` looks up the executor for a `Feed`'s
`source_kind` and calls it — it never imports, names, or special-cases
any concrete connector. In Phase 2 the registry passed to the
orchestration service is intentionally empty: no `FeedSyncExecutor`
for any `FeedSourceKind` exists yet, so every sync trigger fails
honestly with `UnknownFeedConnectorError` (mapped to HTTP 422) until a
later phase registers one — never a silently-successful no-op.

Same instance-based registry shape as
`application.platform.circuit_breaker.CircuitBreakerRegistry`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from redforge.domain.threat_intel.feed_value_objects import FeedSourceKind


@dataclass(frozen=True, slots=True)
class FeedSyncContext:
    """Everything a `FeedSyncExecutor` needs for one synchronization
    attempt. Deliberately does not include the `Feed` aggregate itself
    — the executor operates on read-only configuration data, never
    lifecycle state, so it cannot accidentally bypass `Feed`'s own
    transition methods."""

    feed_id: str
    feed_key: str
    source_kind: FeedSourceKind
    connector_config: dict[str, Any] = field(default_factory=dict)
    credential_ref: str | None = None
    checkpoint: str | None = None


@dataclass(frozen=True, slots=True)
class FeedSyncOutcome:
    """What a `FeedSyncExecutor` returns on a *successful* attempt. On
    failure it raises instead — see `FeedSyncExecutor.execute`."""

    checkpoint: str | None = None
    items_fetched: int = 0
    items_processed: int = 0
    items_failed: int = 0


@runtime_checkable
class FeedSyncExecutor(Protocol):
    """Port a concrete feed connector implements. `execute` performs
    exactly one synchronization attempt (fetch + process, using
    `context.checkpoint` as the resume cursor if the connector supports
    incremental pulls) and either returns a `FeedSyncOutcome` or raises.

    Retryability is the *caller's* decision, not the executor's: the
    orchestration service wraps this call with
    `application.platform.retry_strategy.RetryExecutor` using the
    feed's own `RetryPolicy`, so an executor should simply raise on any
    failure (transient or not) rather than attempting to retry
    internally or swallow errors.
    """

    async def execute(self, context: FeedSyncContext) -> FeedSyncOutcome: ...


class FeedConnectorRegistry:
    """Thread-safe registry mapping `FeedSourceKind` -> `FeedSyncExecutor`.

    Usage (Phase 3+, from connector wiring code — never from this
    module or the orchestration service)::

        registry = FeedConnectorRegistry()
        registry.register(FeedSourceKind.STIX_TAXII_PULL, TaxiiPullExecutor(...))
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._executors: dict[FeedSourceKind, FeedSyncExecutor] = {}

    def register(self, source_kind: FeedSourceKind, executor: FeedSyncExecutor) -> None:
        with self._lock:
            self._executors[source_kind] = executor

    def get(self, source_kind: FeedSourceKind) -> FeedSyncExecutor | None:
        with self._lock:
            return self._executors.get(source_kind)

    def list_registered(self) -> list[FeedSourceKind]:
        with self._lock:
            return list(self._executors.keys())
