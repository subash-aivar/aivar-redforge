"""Enumerations for the execution domain."""

from __future__ import annotations

from enum import StrEnum


class KillSwitchScope(StrEnum):
    ENGAGEMENT = "Engagement"
    OPERATION = "Operation"
    PLATFORM_WIDE = "PlatformWide"


class KillSwitchArmedState(StrEnum):
    ARMED = "Armed"
    TRIGGERED = "Triggered"
    RELEASED = "Released"


class RateLimitDecision(StrEnum):
    PERMITTED = "Permitted"
    THROTTLED = "Throttled"
    FORBIDDEN = "Forbidden"


class ImpactCeiling(StrEnum):
    OBSERVE = "Observe"
    PROBE = "Probe"
    EXPLOIT = "Exploit"
    DESTRUCT = "Destruct"


class JournalEntryType(StrEnum):
    ACTION_STARTED = "ActionStarted"
    ACTION_COMPLETED = "ActionCompleted"
    ACTION_FAILED = "ActionFailed"
    ACTION_ABORTED = "ActionAborted"
    KILL_SWITCH_TRIGGERED = "KillSwitchTriggered"
    SAFETY_CHECK_FAILED = "SafetyCheckFailed"
    SCOPE_VIOLATION_ATTEMPTED = "ScopeViolationAttempted"
    HUMAN_APPROVAL_REQUIRED = "HumanApprovalRequired"
    APPROVAL_GRANTED = "ApprovalGranted"
    APPROVAL_DENIED = "ApprovalDenied"
    ROLLBACK_INITIATED = "RollbackInitiated"
    ROLLBACK_COMPLETED = "RollbackCompleted"
    CORRECTION_ENTRY = "CorrectionEntry"


class ChainIntegrityStatus(StrEnum):
    VERIFIED = "Verified"
    BROKEN = "Broken"


class AttackActionState(StrEnum):
    AUTHORIZED = "Authorized"
    EXECUTING = "Executing"
    COMPLETED = "Completed"
    FAILED = "Failed"
    ABORTED = "Aborted"
    TIMED_OUT = "TimedOut"


class WorkerType(StrEnum):
    CLOUD_AGENT = "CloudAgent"
    EDGE_AGENT = "EdgeAgent"
    CONTAINER_AGENT = "ContainerAgent"
    LOCAL_OPERATOR_AGENT = "LocalOperatorAgent"
    SCHEDULED_AGENT = "ScheduledAgent"


class WorkerHealthStatus(StrEnum):
    HEALTHY = "Healthy"
    DEGRADED = "Degraded"
    UNAVAILABLE = "Unavailable"
    DECOMMISSIONED = "Decommissioned"


class WorkerTrustLevel(StrEnum):
    HIGH_TRUST = "HighTrust"
    STANDARD_TRUST = "StandardTrust"
    LOW_TRUST = "LowTrust"


class ScopeVerificationStatus(StrEnum):
    VERIFIED = "Verified"
    FAILED = "Failed"
    UNAVAILABLE = "Unavailable"


class AuthorizationFailureReason(StrEnum):
    KILL_SWITCH_TRIGGERED = "KillSwitchTriggered"
    SCOPE_VIOLATION = "ScopeViolation"
    RATE_LIMIT_THROTTLED = "RateLimitThrottled"
    RATE_LIMIT_FORBIDDEN = "RateLimitForbidden"
    OUTSIDE_EXECUTION_WINDOW = "OutsideExecutionWindow"
    WORKER_CAPABILITY_INSUFFICIENT = "WorkerCapabilityInsufficient"
    WORKER_TRUST_INSUFFICIENT = "WorkerTrustInsufficient"
    WORKER_UNAVAILABLE = "WorkerUnavailable"
    PAYLOAD_REVOKED = "PayloadRevoked"
    PAYLOAD_NOT_APPROVED = "PayloadNotApproved"
    PAYLOAD_HASH_MISMATCH = "PayloadHashMismatch"


# Oversight roles distinct from redteam:ciso for platform-wide kill switch release
# (Hardening §8).
CISO_ROLE = "redteam:ciso"
OVERSIGHT_ROLES: frozenset[str] = frozenset(
    {
        "legal:oversight",
        "compliance:authority",
    }
)

_IMPACT_RANK: dict[ImpactCeiling, int] = {
    ImpactCeiling.OBSERVE: 1,
    ImpactCeiling.PROBE: 2,
    ImpactCeiling.EXPLOIT: 3,
    ImpactCeiling.DESTRUCT: 4,
}


def impact_rank(ceiling: ImpactCeiling) -> int:
    return _IMPACT_RANK[ceiling]


def trust_allows_impact(trust: WorkerTrustLevel, ceiling: ImpactCeiling) -> bool:
    """LowTrust cannot execute Exploit+ techniques (freeze §10.2)."""
    if trust == WorkerTrustLevel.LOW_TRUST:
        return impact_rank(ceiling) < impact_rank(ImpactCeiling.EXPLOIT)
    return True
