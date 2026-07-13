"""Value objects for the Gated Safe Active Validation bounded context (M11).

This bounded context is genuinely distinct from two other execution-shaped
things already in the codebase:
  - `domain/execution/` (`ExecutionPlan`) — a fully-modeled but entirely
    unwired/dead aggregate (zero callers, zero persistence) from an
    earlier sprint. Left untouched; M11 does not build on it.
  - `domain/validations/` (`ValidationRun`) — owned end-to-end by
    `application/validation_service.py` for LLM prompt/attack validation.
    Unrelated to M11's real-network reconnaissance checks.

`ValidationExecution` (this module's aggregate, in entity.py) is the one
real execution engine M11 adds: bounded, non-destructive, real network
checks (DNS/TCP/TLS/HTTP) against an authorized canonical AITarget,
gated by a fresh M10 ExecutionPolicyService decision before any network
activity.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique


@unique
class ExecutionStatus(StrEnum):
    """Lifecycle status of a ValidationExecution.

    Legal transitions (enforced by ValidationExecution, no others exist):
        PENDING -> POLICY_CHECKING
        POLICY_CHECKING -> AUTHORIZED
        POLICY_CHECKING -> DENIED                  (terminal)
        AUTHORIZED -> RUNNING
        RUNNING -> COMPLETED                       (terminal)
        RUNNING -> PARTIALLY_COMPLETED             (terminal)
        RUNNING -> FAILED                          (terminal)
        {PENDING, POLICY_CHECKING, AUTHORIZED, RUNNING} -> CANCELLED (terminal)

    A DENIED execution never reaches RUNNING — no network step is ever
    scheduled for it. A CANCELLED execution stops scheduling new steps;
    an already-dispatched step is allowed to finish (its result is still
    recorded truthfully).
    """

    PENDING = "pending"
    POLICY_CHECKING = "policy_checking"
    AUTHORIZED = "authorized"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIALLY_COMPLETED = "partially_completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DENIED = "denied"


TERMINAL_EXECUTION_STATUSES: frozenset[ExecutionStatus] = frozenset({
    ExecutionStatus.COMPLETED,
    ExecutionStatus.PARTIALLY_COMPLETED,
    ExecutionStatus.FAILED,
    ExecutionStatus.CANCELLED,
    ExecutionStatus.DENIED,
})


@unique
class StepStatus(StrEnum):
    """Lifecycle status of one ValidationStep. A FAILED step is never
    silently reinterpreted as successful — `ValidationExecution`'s
    completion status is computed from the true set of step statuses,
    never overridden."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


@unique
class StepType(StrEnum):
    """Closed, server-controlled step taxonomy. A client can never
    submit a step — the server builds the plan entirely from the
    canonical target's endpoint scheme (SAFE_ACTIVE_BASELINE_V1) or
    from bounded discovery facts matched against the closed adaptive
    rule registry (NETWORK_DISCOVERY_BASELINE_V1, M12)."""

    DNS_RESOLUTION = "dns_resolution"
    TCP_CONNECTIVITY = "tcp_connectivity"
    TLS_HANDSHAKE = "tls_handshake"
    HTTP_METADATA = "http_metadata"
    HTTP_SECURITY_HEADERS = "http_security_headers"
    SERVICE_REACHABILITY = "service_reachability"
    # M12 — bounded TCP port discovery against the target's own
    # validated resolved-address set (never an arbitrary CIDR/range).
    PORT_DISCOVERY = "port_discovery"
    # M13 — protocol-aware service validation. Each is a single bounded,
    # non-authenticating, non-mutating protocol-level read dispatched
    # only through the closed ProtocolValidatorRegistry — never a raw
    # client-submitted probe.
    SSH_BANNER = "ssh_banner"
    MYSQL_HANDSHAKE = "mysql_handshake"
    POSTGRESQL_HANDSHAKE = "postgresql_handshake"
    REDIS_PING = "redis_ping"


@unique
class ValidationProfile(StrEnum):
    """Closed, server-controlled validation profile taxonomy."""

    SAFE_ACTIVE_BASELINE_V1 = "safe_active_baseline_v1"
    # M12 — discovers a small, versioned, bounded set of ports on the
    # target's own resolved addresses, then adaptively appends only
    # pre-registered safe validation steps for ports the deterministic
    # adaptive rule registry recognizes (443->TLS/HTTPS, 80->HTTP).
    NETWORK_DISCOVERY_BASELINE_V1 = "network_discovery_baseline_v1"


@unique
class ExecutionTrigger(StrEnum):
    """M14 — how a ValidationExecution came to exist. Closed, server-
    assigned at creation time — never a client-supplied field.

    MANUAL: the pre-existing M11-M13 ad-hoc creation path
    (`POST /validation-executions`) — unchanged, defaults to this.
    SCHEDULED: created by the continuous-validation scheduler processor
    at a due boundary it computed and claimed itself.
    ON_DEMAND: an operator-triggered "Run Now" against an existing
    continuous validation policy — goes through the exact same
    processor/reconciliation/drift pipeline as SCHEDULED, but is not
    tied to a specific due boundary (see `scheduled_due_at`, which is
    only ever set for SCHEDULED)."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    ON_DEMAND = "on_demand"


@unique
class StepSource(StrEnum):
    """Where a step in the final executed plan came from. INITIAL steps
    are built once, synchronously, from the profile/target before
    RUNNING begins. ADAPTIVE steps are appended mid-execution by the
    deterministic adaptive rule registry (M12) in response to a
    discovered fact — never client-submitted, never LLM-planned."""

    INITIAL = "initial"
    ADAPTIVE = "adaptive"


@unique
class ExecutionEventType(StrEnum):
    """Closed set of live-progress event types."""

    EXECUTION_CREATED = "execution_created"
    POLICY_CHECK_STARTED = "policy_check_started"
    POLICY_ALLOWED = "policy_allowed"
    POLICY_DENIED = "policy_denied"
    PLAN_CREATED = "plan_created"
    STEP_STARTED = "step_started"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED = "step_failed"
    CONDITION_INGESTED = "condition_ingested"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_PARTIAL = "execution_partial"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_CANCELLED = "execution_cancelled"
    # M12 — adaptive discovery/planning/enrichment events.
    DISCOVERY_STARTED = "discovery_started"
    PORT_REACHABILITY_OBSERVED = "port_reachability_observed"
    ADAPTIVE_RULE_MATCHED = "adaptive_rule_matched"
    STEP_ADDED_TO_PLAN = "step_added_to_plan"
    ASSET_RESOLVED = "asset_resolved"
    SERVICE_CONTEXT_UPDATED = "service_context_updated"
    CORRELATION_EVALUATED = "correlation_evaluated"
    # M15 — closes the two durable-trail gaps found during Security
    # Operations Command Center reconnaissance: AUTHORIZED->RUNNING and
    # an operator's cancellation *request* (distinct from the eventual
    # observed EXECUTION_CANCELLED) previously left no event at all.
    EXECUTION_STARTED = "execution_started"
    CANCELLATION_REQUESTED = "cancellation_requested"


@unique
class DiscoveryPortOutcome(StrEnum):
    """Bounded outcome of one port-discovery check — deliberately finer
    than a bare bool so a policy-blocked address is never confused with
    a genuine network timeout or an actively-refused connection."""

    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    NETWORK_ERROR = "network_error"
    POLICY_BLOCKED = "policy_blocked"


@unique
class ServiceEvidenceState(StrEnum):
    """Explicit service-truth ladder. A port being open (PORT_REACHABLE)
    is never conflated with a protocol-specific hint from the port
    number alone (SERVICE_HINTED) or with real protocol evidence
    actually having been observed (SERVICE_VALIDATED) — see
    ServiceReachabilityResult in network_adapters.py for the same
    reachable-vs-validated distinction M11 already established."""

    PORT_REACHABLE = "port_reachable"
    SERVICE_HINTED = "service_hinted"
    SERVICE_VALIDATED = "service_validated"


@unique
class ProtocolValidationState(StrEnum):
    """M13 — the outcome ladder for one protocol-validator attempt,
    analogous to `DiscoveryPortOutcome` for a bare TCP check but richer:
    a protocol probe can genuinely distinguish "never ran"/"port closed"
    from "got bytes back that don't match the expected protocol shape"
    from "got bytes back that unambiguously do". This is deliberately a
    separate enum from `ServiceEvidenceState` — `ServiceEvidenceState` is
    the asset/event-level truth ladder (do we have ANY evidence for this
    service), while `ProtocolValidationState` is the per-attempt outcome
    a single validator run produces; `ProtocolValidationState.VALIDATED`
    is what causes a `ServiceEvidenceState.SERVICE_VALIDATED` transition,
    never the other way around."""

    NOT_ATTEMPTED = "not_attempted"
    UNREACHABLE = "unreachable"
    INCONCLUSIVE = "inconclusive"
    HINTED = "hinted"
    VALIDATED = "validated"
    ERROR = "error"


@unique
class AddressClass(StrEnum):
    """Network-boundary classification of a resolved IP address. Only
    PUBLIC is permitted for active validation in M11 — see
    `application/validation_execution/network_boundary.py` for the full
    reasoning. This is a deliberate, documented v1 scope limit: no
    per-authorization "explicit internal range" allowance exists yet in
    M10's scope model, so private/loopback/link-local/reserved/
    multicast/metadata addresses are denied categorically rather than
    conditionally — never a fabricated conditional allowance."""

    PUBLIC = "public"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    PRIVATE = "private"
    MULTICAST = "multicast"
    RESERVED = "reserved"
    METADATA = "metadata"
    UNSPECIFIED = "unspecified"


ALLOWED_ADDRESS_CLASSES: frozenset[AddressClass] = frozenset({AddressClass.PUBLIC})


@dataclass(frozen=True, slots=True)
class ExecutionLimits:
    """Immutable snapshot of the effective bounds used for one execution
    — persisted alongside the execution so a later profile-version bump
    never silently changes the interpretation of historical runs.

    These are the ONLY knobs — there is no per-request override; a
    client can select a profile, never these values.
    """

    max_steps: int = 6
    max_resolved_addresses: int = 4
    max_ports: int = 4
    per_step_timeout_seconds: float = 5.0
    total_execution_timeout_seconds: float = 30.0
    redirect_limit: int = 3
    max_concurrency: int = 1
    max_events: int = 200
    max_evidence_items_per_step: int = 5
    max_evidence_value_length: int = 500
    dns_retry_attempts: int = 2
    # M12 — discovery-specific bounds. Defaulted (never used) for
    # SAFE_ACTIVE_BASELINE_V1 so historical M11 executions' persisted
    # `limits` JSON deserializes identically (new fields, old meaning).
    discovery_port_policy_version: int = 0
    max_adaptive_steps: int = 0

    @classmethod
    def default_for(cls, profile: ValidationProfile) -> ExecutionLimits:
        if profile == ValidationProfile.SAFE_ACTIVE_BASELINE_V1:
            return cls()
        if profile == ValidationProfile.NETWORK_DISCOVERY_BASELINE_V1:
            return cls(
                max_steps=12,
                max_ports=9,
                max_evidence_items_per_step=12,
                total_execution_timeout_seconds=45.0,
                discovery_port_policy_version=2,
                # M13 adds 4 protocol-candidate rules (SSH/MySQL/
                # PostgreSQL/Redis) on top of M12's up-to-3 HTTP/TLS
                # adaptive steps — a fully multi-protocol-reachable
                # target can genuinely produce 7 adaptive steps in one
                # run (proven in the owned local lab). Raised from 6 to
                # 8: exactly enough for every registered rule to fire
                # simultaneously, plus one unit of headroom — not an
                # arbitrary increase.
                max_adaptive_steps=8,
            )
        raise ValueError(f"No default limits defined for profile '{profile}'")


@unique
class ErrorCategory(StrEnum):
    """Closed error-category taxonomy for a FAILED step — never a raw
    exception string persisted (avoids leaking internals/stack traces
    into evidence)."""

    TIMEOUT = "timeout"
    CONNECTION_REFUSED = "connection_refused"
    DNS_FAILURE = "dns_failure"
    TLS_FAILURE = "tls_failure"
    NETWORK_BOUNDARY_DENIED = "network_boundary_denied"
    REDIRECT_LIMIT_EXCEEDED = "redirect_limit_exceeded"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"
    # M12 — an adaptive step whose fresh, immediately-pre-dispatch M10
    # policy check did not return ALLOW. Distinct from
    # NETWORK_BOUNDARY_DENIED (an SSRF/scope denial): this is an
    # authorization-state denial at time of use.
    POLICY_DENIED = "policy_denied"
    # M13 — bytes were read back from the port but do not match the
    # expected protocol's identification shape (e.g. no SSH banner
    # prefix, no MySQL/PostgreSQL handshake packet shape). Distinct from
    # CONNECTION_REFUSED/TIMEOUT (no bytes at all) and from TLS_FAILURE
    # (a real TLS negotiation attempt failed) — this is "we got a reply,
    # it just isn't this protocol", the concrete signal behind
    # ProtocolValidationState.INCONCLUSIVE.
    PROTOCOL_MISMATCH = "protocol_mismatch"
