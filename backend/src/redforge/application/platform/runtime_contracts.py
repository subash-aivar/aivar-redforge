"""Runtime & Operations Platform protocols — Sprint 26.

Twelve protocol ports for the Enterprise Runtime & Operations Platform.
All are @runtime_checkable and vendor-neutral — no Prometheus, OTel, or
Datadog imports. Adapters implement these to plug in any backend.

Design rules:
- No imports from infrastructure layer.
- No vendor-specific types.
- All async methods that touch I/O.
- Sync methods for hot-path operations (record_counter, etc.).
"""

from __future__ import annotations

import dataclasses
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Sequence
    from datetime import datetime


# ── Shared enumerations ────────────────────────────────────────────────────


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class WorkerState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"
    RESTARTING = "restarting"


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class MetricType(StrEnum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"


class AlertSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class LifecyclePhase(StrEnum):
    INITIALIZING = "initializing"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"


# ── Value objects ──────────────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True, slots=True)
class ComponentHealth:
    component_id: str
    component_type: str
    status: HealthStatus
    message: str
    checked_at: datetime
    details: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class AggregatedHealth:
    overall_status: HealthStatus
    components: tuple[ComponentHealth, ...]
    checked_at: datetime

    def component(self, component_id: str) -> ComponentHealth | None:
        for c in self.components:
            if c.component_id == component_id:
                return c
        return None


@dataclasses.dataclass(frozen=True, slots=True)
class WorkerHealth:
    worker_id: str
    state: WorkerState
    restart_count: int
    last_started_at: datetime | None
    last_failed_at: datetime | None
    error_message: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class ProjectionHealth:
    projection_name: str
    state: WorkerState
    restart_count: int
    last_event_position: int
    poison_event_count: int
    last_failed_at: datetime | None
    error_message: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class DeadLetterEntry:
    entry_id: str
    source_projection: str
    event_id: str
    event_type: str
    payload: Any
    error_message: str
    retry_count: int
    first_failed_at: datetime
    last_failed_at: datetime
    organization_id: str


@dataclasses.dataclass(frozen=True, slots=True)
class MetricSample:
    name: str
    value: float
    metric_type: MetricType
    labels: tuple[tuple[str, str], ...]
    sampled_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    severity: AlertSeverity
    component_id: str
    title: str
    message: str
    labels: dict[str, str]
    fired_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class Heartbeat:
    component_id: str
    beat_at: datetime
    sequence: int
    metadata: dict[str, Any] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True, slots=True)
class RecoveryResult:
    component_id: str
    succeeded: bool
    strategy_used: str
    attempts: int
    recovered_at: datetime
    error_message: str | None


@dataclasses.dataclass(frozen=True, slots=True)
class RuntimeSnapshot:
    snapshot_id: str
    taken_at: datetime
    health: AggregatedHealth
    dlq_depth: int
    active_workers: int
    active_projections: int
    circuit_states: dict[str, str]
    metrics_summary: dict[str, float]


# ── Protocols ──────────────────────────────────────────────────────────────


@runtime_checkable
class HealthChecker(Protocol):
    """Single-component health check.

    Each component (projection, worker, DB, KG, connector…) implements this.
    The RuntimeHealthEngine aggregates all registered checkers.
    """

    async def check(self) -> ComponentHealth:
        """Run the health check and return current health status."""
        ...


@runtime_checkable
class MetricsCollector(Protocol):
    """Vendor-neutral metrics interface.

    Implementations plug in Prometheus, Datadog, StatsD, or InMemory for tests.
    All label sets are tuples of (name, value) pairs for hashability.
    """

    def record_counter(
        self,
        name: str,
        value: float = 1.0,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Increment a counter metric."""
        ...

    def record_gauge(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Set a gauge metric to an absolute value."""
        ...

    def record_histogram(
        self,
        name: str,
        value: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Record an observation in a histogram/distribution."""
        ...


@runtime_checkable
class AlertPublisher(Protocol):
    """Publishes operational alerts to external channels.

    Implementations may deliver to PagerDuty, Slack, email, or a log sink.
    The interface is fire-and-forget (no ack required from this layer).
    """

    async def publish(self, alert: Alert) -> None:
        """Publish a single alert to all configured channels."""
        ...


@runtime_checkable
class DeadLetterStore(Protocol):
    """Persistent storage for events that could not be processed.

    DLQ entries survive process restarts. Callers may requeue them for
    retry or discard them after investigation.
    """

    async def store(self, entry: DeadLetterEntry) -> None:
        """Store a failed event in the dead-letter queue."""
        ...

    async def list(
        self,
        organization_id: str,
        source_projection: str | None = None,
        max_count: int | None = None,
    ) -> Sequence[DeadLetterEntry]:
        """List DLQ entries, optionally filtered by source projection."""
        ...

    async def requeue(self, entry_id: str) -> DeadLetterEntry:
        """Return entry with incremented retry_count (does not auto-replay)."""
        ...

    async def discard(self, entry_id: str) -> None:
        """Permanently remove an entry from the DLQ."""
        ...

    async def depth(self, organization_id: str) -> int:
        """Return total number of entries for an organisation."""
        ...


@runtime_checkable
class RuntimeDLQ(Protocol):
    """Extended DLQ contract used internally by the runtime platform.

    Combines DeadLetterStore with replay lifecycle methods needed by
    DLQReplayWorker and operational status endpoints.

    Both InMemoryDeadLetterQueue and PostgreSQLDeadLetterQueue satisfy
    this protocol via structural subtyping.
    """

    async def store(self, entry: DeadLetterEntry) -> None: ...

    async def list(
        self,
        organization_id: str,
        source_projection: str | None = None,
        max_count: int | None = None,
    ) -> Sequence[DeadLetterEntry]: ...

    async def requeue(self, entry_id: str) -> DeadLetterEntry: ...

    async def discard(self, entry_id: str) -> None: ...

    async def depth(self, organization_id: str) -> int: ...

    async def total_depth(self) -> int:
        """Return total entry count across all organisations."""
        ...

    async def list_pending_replay(self, max_count: int = 100) -> Sequence[DeadLetterEntry]:
        """Atomically claim and return entries for replay (status=requeued).

        Claimed entries are moved to status=in_flight with a reserved_until
        timestamp. Concurrent workers cannot claim the same entry. Expired
        reservations (reserved_until < NOW()) are re-claimable.
        """
        ...

    async def mark_replayed(self, entry_id: str) -> None:
        """Remove an entry after successful replay."""
        ...

    async def mark_exhausted(self, entry_id: str) -> None:
        """Transition an entry to the terminal exhausted state.

        Called when retry_count exceeds the configured threshold. Exhausted
        entries are never picked up for replay again and must be investigated
        and discarded manually by an operator.
        """
        ...

    async def release_inflight(self, entry_id: str) -> None:
        """Return a claimed in-flight entry to requeued state after replay failure.

        Clears reserved_until so the entry becomes claimable again on the
        next poll cycle. Increments version for optimistic concurrency.
        """
        ...


@runtime_checkable
class WorkerSupervisor(Protocol):
    """Supervises long-running async worker tasks.

    Restart policy and backoff are implementation details.
    The supervisor escalates to alert after max_restarts.
    """

    async def start_worker(self, worker_id: str) -> None:
        """Start a registered worker by ID."""
        ...

    async def stop_worker(self, worker_id: str) -> None:
        """Stop a running worker gracefully."""
        ...

    async def restart_worker(self, worker_id: str) -> None:
        """Stop and re-start a worker. Resets the failure count."""
        ...

    async def worker_health(self, worker_id: str) -> WorkerHealth:
        """Return health snapshot for a specific worker."""
        ...

    def list_workers(self) -> Sequence[str]:
        """Return all registered worker IDs."""
        ...


@runtime_checkable
class ProjectionSupervisor(Protocol):
    """Supervises named projections managed by an IdempotentProjectionEngine.

    Handles: restart on failure, poison-event detection, checkpoint validation,
    and failure escalation to DLQ.
    """

    async def start(self, projection_name: str) -> None:
        """Start or resume a projection."""
        ...

    async def stop(self, projection_name: str) -> None:
        """Stop a running projection gracefully."""
        ...

    async def restart(self, projection_name: str) -> None:
        """Restart a projection, preserving its checkpoint."""
        ...

    async def health(self, projection_name: str) -> ProjectionHealth:
        """Return health snapshot for a specific projection."""
        ...

    def list_projections(self) -> Sequence[str]:
        """Return all supervised projection names."""
        ...


@runtime_checkable
class RuntimeMonitor(Protocol):
    """Collects a full runtime snapshot from all subsystems."""

    async def snapshot(self) -> RuntimeSnapshot:
        """Return a point-in-time snapshot of the entire runtime."""
        ...

    async def aggregate_health(self) -> AggregatedHealth:
        """Return aggregated health across all registered health checkers."""
        ...


@runtime_checkable
class CircuitBreaker(Protocol):
    """Three-state circuit breaker (Closed → Open → Half-Open → Closed).

    Prevents cascading failures by stopping calls to a failing dependency
    during the OPEN phase and probing recovery in HALF_OPEN.
    """

    async def execute(
        self,
        coro_factory: Callable[[], Awaitable[Any]],
    ) -> Any:
        """Execute the coroutine if the circuit allows. Raises CircuitOpenError
        when OPEN. Transitions state on success/failure.
        """
        ...

    @property
    def state(self) -> CircuitState:
        """Current circuit state."""
        ...

    @property
    def failure_count(self) -> int:
        """Number of failures in the current sliding window."""
        ...


@runtime_checkable
class BackpressureController(Protocol):
    """Controls flow between fast producers and slow consumers.

    Implementations use token buckets, semaphores, or adaptive delays.
    All callers must pair acquire() with release() (or use execute()).
    """

    async def acquire(self) -> None:
        """Acquire a processing slot. Blocks when at high watermark."""
        ...

    def release(self) -> None:
        """Release a processing slot."""
        ...

    @property
    def is_throttled(self) -> bool:
        """True when the controller is actively throttling producers."""
        ...

    @property
    def queue_depth(self) -> int:
        """Current number of in-flight items."""
        ...


@runtime_checkable
class LifecycleCoordinator(Protocol):
    """Coordinates ordered startup and graceful shutdown.

    Startup hooks run in registration order.
    Shutdown hooks run in reverse registration order.
    """

    async def startup(self) -> None:
        """Run all startup hooks in registration order."""
        ...

    async def shutdown(self, timeout_s: float = 30.0) -> None:
        """Run all shutdown hooks in reverse order. Cancel stragglers after timeout."""
        ...

    def register_startup(self, name: str, fn: Callable[[], Awaitable[None]]) -> None:
        """Register an async function to run during startup."""
        ...

    def register_shutdown(self, name: str, fn: Callable[[], Awaitable[None]]) -> None:
        """Register an async function to run during shutdown."""
        ...

    @property
    def phase(self) -> LifecyclePhase:
        """Current lifecycle phase."""
        ...


@runtime_checkable
class HeartbeatProvider(Protocol):
    """Emits periodic heartbeats to signal liveness.

    Missing heartbeats are detected by HeartbeatMonitor.is_alive().
    """

    async def beat(self) -> Heartbeat:
        """Emit a heartbeat for this component."""
        ...

    @property
    def component_id(self) -> str:
        """Identifier of this component."""
        ...

    @property
    def is_alive(self) -> bool:
        """True if the last beat was within the expected interval."""
        ...


@runtime_checkable
class RecoveryCoordinator(Protocol):
    """Coordinates recovery actions for failed components.

    Implements pluggable recovery strategies: restart, reconnect,
    checkpoint rollback, or escalation.
    """

    async def recover(self, component_id: str) -> RecoveryResult:
        """Attempt recovery of a failed component."""
        ...

    async def can_recover(self, component_id: str) -> bool:
        """Return True if a recovery strategy exists for this component."""
        ...
