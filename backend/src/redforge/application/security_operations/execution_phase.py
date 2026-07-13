"""Backend-derived ExecutionPhase mapping — M15.

Every ExecutionEventType maps to exactly one ExecutionPhase, used ONLY
by the execution telemetry detail view (never the frontend). An event
type genuinely not yet mapped resolves to UNKNOWN rather than raising —
matching every other closed-enum-with-UNKNOWN-fallback convention in
this codebase (SourceDomain, RuntimeComponentStatus, etc.).
"""

from __future__ import annotations

from redforge.domain.security_operations.value_objects import ExecutionPhase

_EVENT_TYPE_TO_PHASE: dict[str, ExecutionPhase] = {
    "execution_created": ExecutionPhase.AUTHORIZATION,
    "policy_check_started": ExecutionPhase.AUTHORIZATION,
    "policy_allowed": ExecutionPhase.AUTHORIZATION,
    "policy_denied": ExecutionPhase.AUTHORIZATION,
    "plan_created": ExecutionPhase.RESOLUTION,
    "execution_started": ExecutionPhase.RESOLUTION,
    "discovery_started": ExecutionPhase.DISCOVERY,
    "port_reachability_observed": ExecutionPhase.DISCOVERY,
    "asset_resolved": ExecutionPhase.DISCOVERY,
    "adaptive_rule_matched": ExecutionPhase.ADAPTIVE_VALIDATION,
    "step_added_to_plan": ExecutionPhase.ADAPTIVE_VALIDATION,
    "service_context_updated": ExecutionPhase.PROTOCOL_VALIDATION,
    "step_started": ExecutionPhase.SERVICE_VALIDATION,
    "step_completed": ExecutionPhase.SERVICE_VALIDATION,
    "step_failed": ExecutionPhase.SERVICE_VALIDATION,
    "condition_ingested": ExecutionPhase.CONDITION_PROCESSING,
    "correlation_evaluated": ExecutionPhase.CORRELATION,
    "execution_completed": ExecutionPhase.COMPLETED,
    "execution_partial": ExecutionPhase.COMPLETED,
    "execution_failed": ExecutionPhase.COMPLETED,
    "execution_cancelled": ExecutionPhase.COMPLETED,
    "cancellation_requested": ExecutionPhase.SERVICE_VALIDATION,
}


_PROTOCOL_STEP_TYPES = frozenset({
    "ssh_banner", "mysql_handshake", "postgresql_handshake", "redis_ping",
})
_STEP_LEVEL_EVENT_TYPES = frozenset({"step_started", "step_completed", "step_failed"})


def phase_for_event_type(event_type: str, step_type: str | None = None) -> ExecutionPhase:
    """`step_type` (from the event's own payload, when present) refines
    a generic step-level event into PROTOCOL_VALIDATION for the 4 M13
    protocol-validated step types — everything else uses the closed
    per-event-type mapping above."""
    if event_type in _STEP_LEVEL_EVENT_TYPES and step_type in _PROTOCOL_STEP_TYPES:
        return ExecutionPhase.PROTOCOL_VALIDATION
    return _EVENT_TYPE_TO_PHASE.get(event_type, ExecutionPhase.UNKNOWN)
