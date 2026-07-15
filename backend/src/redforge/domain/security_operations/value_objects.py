"""Value objects for the Security Operations bounded context (M15).

Every enum here is closed and server-owned. A client can filter by
these values; it can never define a new one, and an unrecognized
internal value must always degrade to UNKNOWN rather than crash or
silently disappear.
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class SourceDomain(StrEnum):
    """The closed set of bounded contexts M15 knows how to project.

    Only domains with a real, implemented event producer are listed.
    AI_RED_TEAM/campaign activity is deliberately excluded — no
    canonical campaign execution event producer feeds platform_events
    as of M15; adding this enum member without a real source would be
    exactly the kind of fabricated source domain the brief prohibits.
    """

    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    CONTINUOUS_VALIDATION = "continuous_validation"
    SECURITY_DRIFT = "security_drift"
    SECURITY_CONDITION = "security_condition"
    SECURITY_CORRELATION = "security_correlation"
    RUNTIME = "runtime"
    # M16 — real producers: network_validation_run_events and
    # network_monitoring_policy_lifecycle_events (see
    # infrastructure/database/repositories/network_security/event_repository.py).
    NETWORK_SECURITY = "network_security"
    # M19 — DDoS incident events from ddos_incident_events table
    DDOS = "ddos"
    UNKNOWN = "unknown"


@unique
class OperationalImportance(StrEnum):
    """A controlled operational importance classification.

    Deliberately NOT a CVSS-like universal score. Mapping from internal
    event type to importance is server-controlled, deterministic, and
    tested (see application/security_operations/projection_registry.py)
    — never computed in the browser, never inferred from bare
    reachability, never inferred from a version banner.
    """

    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


@unique
class ExecutionPhase(StrEnum):
    """Backend-derived phase of a ValidationExecution, for telemetry.

    Only a phase backed by an actual durable ExecutionEvent or
    execution/step state is ever returned — an execution that hasn't
    reached a given phase simply doesn't report it; unmapped internal
    event types resolve to UNKNOWN, never a fabricated phase.
    """

    AUTHORIZATION = "authorization"
    RESOLUTION = "resolution"
    DISCOVERY = "discovery"
    SERVICE_VALIDATION = "service_validation"
    ADAPTIVE_VALIDATION = "adaptive_validation"
    PROTOCOL_VALIDATION = "protocol_validation"
    CONDITION_PROCESSING = "condition_processing"
    CORRELATION = "correlation"
    SNAPSHOT = "snapshot"
    DRIFT = "drift"
    COMPLETED = "completed"
    UNKNOWN = "unknown"


@unique
class RuntimeComponentStatus(StrEnum):
    """Mirrors application/platform/runtime_contracts.py's HealthStatus
    values, kept as a distinct enum in this bounded context to avoid a
    read-model-to-platform-internals coupling on a type identity basis."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# Bounded query periods for the summary/change-feed endpoints. Server
# controlled and closed — a client cannot supply an arbitrary date
# range or SQL expression.
@unique
class BoundedPeriod(StrEnum):
    ONE_HOUR = "1h"
    TWENTY_FOUR_HOURS = "24h"
    SEVEN_DAYS = "7d"
    THIRTY_DAYS = "30d"


_BOUNDED_PERIOD_SECONDS: dict[BoundedPeriod, int] = {
    BoundedPeriod.ONE_HOUR: 3600,
    BoundedPeriod.TWENTY_FOUR_HOURS: 86400,
    BoundedPeriod.SEVEN_DAYS: 7 * 86400,
    BoundedPeriod.THIRTY_DAYS: 30 * 86400,
}


def bounded_period_seconds(period: BoundedPeriod) -> int:
    return _BOUNDED_PERIOD_SECONDS[period]


# Server-controlled stream tuning. Not client-configurable.
STREAM_BATCH_SIZE = 200
STREAM_HEARTBEAT_INTERVAL_SECONDS = 15.0
STREAM_POLL_INTERVAL_SECONDS = 1.0
# Commit-visibility safety margin: platform_events' global_position is
# allocated from a sequence and is unique but NOT strictly
# commit-order-monotonic under concurrent transactions (see
# infrastructure/platform/event_store.py's own module docstring). A row
# is only surfaced to an SSE client once it is older than this margin,
# giving any concurrently-committing lower-position transaction time to
# land — this bounds freshness latency in exchange for never silently
# skipping an event. Set to a small multiple of the poll interval.
EVENT_VISIBILITY_LAG_SECONDS = 2.0
CHANGE_FEED_MAX_PAGE_SIZE = 200
EXECUTIONS_MAX_PAGE_SIZE = 100
