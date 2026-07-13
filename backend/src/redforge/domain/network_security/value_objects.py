"""Value objects for the Network Security bounded context — M16."""

from __future__ import annotations

from enum import StrEnum, unique

# Re-exported for convenience so application/infra code can import the
# canonical drift taxonomy from this package without reaching into M14's
# module directly — but the enum itself is NOT redefined (see
# domain/network_security/__init__.py's reuse table).
from redforge.domain.continuous_validation.value_objects import (
    CLAIM_LEASE_SECONDS,
    PolicyLifecycle,
    SecurityDriftCategory,
    ValidationCadence,
    cadence_interval_seconds,
    is_legal_policy_transition,
)

__all__ = [
    "CLAIM_LEASE_SECONDS",
    "NETWORK_DRIFT_CATEGORIES",
    "TERMINAL_RUN_STATUSES",
    "NetworkRunStatus",
    "NetworkScopeReasonCode",
    "NetworkValidationProfile",
    "PlanStepType",
    "PolicyLifecycle",
    "SecurityDriftCategory",
    "ValidationCadence",
    "cadence_interval_seconds",
    "is_legal_network_run_transition",
    "is_legal_policy_transition",
]

# Drift categories a network validation run can genuinely produce with
# today's evidence (TCP reachability + M13 protocol/TLS validators +
# M8 conditions + M9 correlations) — the exact same subset M14 itself
# already proves is evidence-backed. CORRELATION_REACTIVATED remains
# excluded for the identical reason M14 excludes it (see
# SecurityDriftCategory's own docstring).
NETWORK_DRIFT_CATEGORIES: frozenset[SecurityDriftCategory] = frozenset({
    SecurityDriftCategory.IP_OBSERVED,
    SecurityDriftCategory.IP_NO_LONGER_OBSERVED,
    SecurityDriftCategory.PORT_BECAME_REACHABLE,
    SecurityDriftCategory.PORT_NO_LONGER_REACHABLE,
    SecurityDriftCategory.PROTOCOL_VALIDATED,
    SecurityDriftCategory.PROTOCOL_NO_LONGER_VALIDATED,
    SecurityDriftCategory.PROTOCOL_CHANGED,
    SecurityDriftCategory.TLS_CERTIFICATE_CHANGED,
    SecurityDriftCategory.CONDITION_APPEARED,
    SecurityDriftCategory.CONDITION_RESOLVED,
    # CONDITION_REACTIVATED IS provable here (unlike CORRELATION_
    # REACTIVATED below): SecurityConditionDTO.first_observed_at gives
    # the exact evidence M14's own processor.py uses for the identical
    # classification — see orchestrator.py's _compute_reactivated_keys().
    SecurityDriftCategory.CONDITION_REACTIVATED,
    SecurityDriftCategory.CORRELATION_APPEARED,
    SecurityDriftCategory.CORRELATION_RESOLVED,
})


@unique
class NetworkValidationProfile(StrEnum):
    """Closed, server-controlled network validation profile taxonomy.

    No client ever supplies scanner flags/arguments/port ranges — a
    profile name is the ONLY input, and each profile's concrete,
    deterministic behavior is defined entirely server-side in
    application/network_security/planner.py.

    - NETWORK_BASELINE: revalidate previously-known services only
      (this authorized target's own current AIAsset SERVICE inventory).
      No new port discovery.
    - NETWORK_STANDARD: NETWORK_BASELINE plus a small, fixed,
      server-controlled common-service port set (reuses M6's
      well-known-port table).
    - NETWORK_DEEP_SAFE: NETWORK_STANDARD plus a bounded, fixed,
      server-controlled extended port set. Still never 1-65535 —
      unrestricted full-port scanning is explicitly out of scope for
      M16 (see planner.py's docstring).
    """

    NETWORK_BASELINE = "network_baseline"
    NETWORK_STANDARD = "network_standard"
    NETWORK_DEEP_SAFE = "network_deep_safe"


@unique
class PlanStepType(StrEnum):
    """Closed, typed validation-plan step taxonomy. Never a free-form
    command/script/module — see planner.py's docstring. No step type
    here can execute a client-supplied action of any kind."""

    RESOLVE_TARGET = "resolve_target"
    VALIDATE_SCOPE = "validate_scope"
    HOST_REACHABILITY = "host_reachability"
    TCP_SERVICE_DISCOVERY = "tcp_service_discovery"
    SERVICE_REVALIDATION = "service_revalidation"
    PROTOCOL_VALIDATION = "protocol_validation"
    TLS_VALIDATION = "tls_validation"
    SNAPSHOT = "snapshot"
    DRIFT = "drift"
    CONDITION_RECONCILIATION = "condition_reconciliation"
    CORRELATION_EVALUATION = "correlation_evaluation"


@unique
class NetworkRunStatus(StrEnum):
    """Lifecycle status of a NetworkValidationRun. Mirrors
    domain.validation_execution.value_objects.ExecutionStatus's exact
    transition graph — a deliberate parallel, not a copy-paste
    accident: see domain/network_security/__init__.py's reuse table for
    why ValidationExecution itself could not be reused directly.

    Legal transitions (enforced by NetworkValidationRun, no others exist):
        PENDING -> POLICY_CHECKING
        POLICY_CHECKING -> AUTHORIZED
        POLICY_CHECKING -> DENIED                  (terminal)
        AUTHORIZED -> RUNNING
        RUNNING -> COMPLETED                       (terminal)
        RUNNING -> PARTIALLY_COMPLETED             (terminal)
        RUNNING -> FAILED                          (terminal)
        {PENDING, POLICY_CHECKING, AUTHORIZED, RUNNING} -> CANCELLED (terminal)
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


TERMINAL_RUN_STATUSES: frozenset[NetworkRunStatus] = frozenset({
    NetworkRunStatus.COMPLETED,
    NetworkRunStatus.PARTIALLY_COMPLETED,
    NetworkRunStatus.FAILED,
    NetworkRunStatus.CANCELLED,
    NetworkRunStatus.DENIED,
})

_RUN_TRANSITIONS: dict[NetworkRunStatus, frozenset[NetworkRunStatus]] = {
    NetworkRunStatus.PENDING: frozenset({
        NetworkRunStatus.POLICY_CHECKING, NetworkRunStatus.CANCELLED,
    }),
    NetworkRunStatus.POLICY_CHECKING: frozenset({
        NetworkRunStatus.AUTHORIZED, NetworkRunStatus.DENIED, NetworkRunStatus.CANCELLED,
    }),
    NetworkRunStatus.AUTHORIZED: frozenset({
        NetworkRunStatus.RUNNING, NetworkRunStatus.CANCELLED,
    }),
    NetworkRunStatus.RUNNING: frozenset({
        NetworkRunStatus.COMPLETED, NetworkRunStatus.PARTIALLY_COMPLETED,
        NetworkRunStatus.FAILED, NetworkRunStatus.CANCELLED,
    }),
    NetworkRunStatus.COMPLETED: frozenset(),
    NetworkRunStatus.PARTIALLY_COMPLETED: frozenset(),
    NetworkRunStatus.FAILED: frozenset(),
    NetworkRunStatus.CANCELLED: frozenset(),
    NetworkRunStatus.DENIED: frozenset(),
}


def is_legal_network_run_transition(current: NetworkRunStatus, target: NetworkRunStatus) -> bool:
    return target in _RUN_TRANSITIONS.get(current, frozenset())


@unique
class NetworkScopeReasonCode(StrEnum):
    """Server-controlled reason codes for a network authorization scope
    decision — mirrors M10's own ReasonCode discipline (closed enum,
    never a free string, never leaks internal detail)."""

    ALLOWED_BY_ACTIVE_AUTHORIZATION = "ALLOWED_BY_ACTIVE_AUTHORIZATION"
    NO_MATCHING_AUTHORIZATION = "NO_MATCHING_AUTHORIZATION"
    AUTHORIZATION_NOT_ACTIVE = "AUTHORIZATION_NOT_ACTIVE"
    AUTHORIZATION_EXPIRED = "AUTHORIZATION_EXPIRED"
    ADDRESS_CLASS_HARD_DENIED = "ADDRESS_CLASS_HARD_DENIED"
    ACTION_CLASS_NOT_IN_SCOPE = "ACTION_CLASS_NOT_IN_SCOPE"
    NETWORK_SCOPE_TOO_LARGE = "NETWORK_SCOPE_TOO_LARGE"
    TENANT_MISMATCH = "TENANT_MISMATCH"
