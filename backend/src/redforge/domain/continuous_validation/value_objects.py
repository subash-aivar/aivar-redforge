"""Value objects for the Continuous Validation bounded context (M14).

Naming deliberately avoids two pre-existing, unwired, name-colliding
modules discovered during reconnaissance: `application/scheduler.py`
(a dead "ValidationSchedule"/"ScheduleStatus" scaffold targeting the
wrong execution boundary) and `domain/posture/` (an unrelated LLM
attack-result drift concept already owning "DriftType"/"DriftEvent").
"""

from __future__ import annotations

from enum import StrEnum, unique


@unique
class PolicyLifecycle(StrEnum):
    """Lifecycle status of a ContinuousValidationPolicy.

    Legal transitions (enforced by ContinuousValidationPolicy, no others
    exist):
        DRAFT -> ACTIVE
        DRAFT -> DISABLED
        ACTIVE -> PAUSED
        ACTIVE -> DISABLED
        PAUSED -> ACTIVE
        PAUSED -> DISABLED

    DISABLED is terminal — it must never silently reactivate. An
    operator who wants continuous validation again must create a new
    policy, exactly mirroring how a REJECTED/EXPIRED SecurityAuthorization
    (M10) is never resurrected in place.
    """

    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"


_POLICY_LIFECYCLE_TRANSITIONS: dict[PolicyLifecycle, frozenset[PolicyLifecycle]] = {
    PolicyLifecycle.DRAFT: frozenset({PolicyLifecycle.ACTIVE, PolicyLifecycle.DISABLED}),
    PolicyLifecycle.ACTIVE: frozenset({PolicyLifecycle.PAUSED, PolicyLifecycle.DISABLED}),
    PolicyLifecycle.PAUSED: frozenset({PolicyLifecycle.ACTIVE, PolicyLifecycle.DISABLED}),
    PolicyLifecycle.DISABLED: frozenset(),  # terminal
}


def is_legal_policy_transition(current: PolicyLifecycle, target: PolicyLifecycle) -> bool:
    return target in _POLICY_LIFECYCLE_TRANSITIONS.get(current, frozenset())


@unique
class ValidationCadence(StrEnum):
    """Closed, server-controlled cadence registry. No client-supplied
    cron expression anywhere in this bounded context — see the M14
    brief's explicit "No arbitrary cron expression from clients"
    prohibition. Every member has a fixed interval in
    `_CADENCE_INTERVAL_SECONDS` used for deterministic next-due
    computation; all due-time arithmetic is anchored to UTC."""

    HOURLY = "hourly"
    EVERY_6_HOURS = "every_6_hours"
    DAILY = "daily"
    WEEKLY = "weekly"


_CADENCE_INTERVAL_SECONDS: dict[ValidationCadence, int] = {
    ValidationCadence.HOURLY: 3_600,
    ValidationCadence.EVERY_6_HOURS: 6 * 3_600,
    ValidationCadence.DAILY: 24 * 3_600,
    ValidationCadence.WEEKLY: 7 * 24 * 3_600,
}


def cadence_interval_seconds(cadence: ValidationCadence) -> int:
    return _CADENCE_INTERVAL_SECONDS[cadence]


@unique
class SecurityDriftCategory(StrEnum):
    """Closed taxonomy of canonical-state changes a revalidation run may
    observe. Only categories genuinely provable from existing M11-M13
    evidence are implemented — CORRELATION_REACTIVATED is deliberately
    excluded: M9's `resolve_stale_for_rule` only ever creates fresh rows
    on re-evaluation (see security_correlation_repository.py), so a
    resolved correlation reappearing is observably indistinguishable
    from CORRELATION_APPEARED, and claiming otherwise would be a
    fabricated distinction this bounded context cannot prove."""

    IP_OBSERVED = "ip_observed"
    IP_NO_LONGER_OBSERVED = "ip_no_longer_observed"
    PORT_BECAME_REACHABLE = "port_became_reachable"
    PORT_NO_LONGER_REACHABLE = "port_no_longer_reachable"
    PROTOCOL_VALIDATED = "protocol_validated"
    PROTOCOL_NO_LONGER_VALIDATED = "protocol_no_longer_validated"
    PROTOCOL_CHANGED = "protocol_changed"
    TLS_CERTIFICATE_CHANGED = "tls_certificate_changed"
    CONDITION_APPEARED = "condition_appeared"
    CONDITION_RESOLVED = "condition_resolved"
    CONDITION_REACTIVATED = "condition_reactivated"
    CORRELATION_APPEARED = "correlation_appeared"
    CORRELATION_RESOLVED = "correlation_resolved"


# Bounded lease window for a scheduler worker's claim on a due policy.
# Chosen well above any single ValidationExecution's own worst-case
# duration (ExecutionLimits caps steps/timeouts far below this) so a
# healthy worker never loses its own claim mid-run, while a crashed
# worker's claim is reclaimable by another worker rather than being
# permanently locked.
CLAIM_LEASE_SECONDS = 300
