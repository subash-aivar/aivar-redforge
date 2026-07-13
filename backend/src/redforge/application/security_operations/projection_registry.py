"""Operational event projection registry — M15.

Maps a raw internal row (validation_execution_events /
security_drift_events / continuous_validation_policy_lifecycle_events /
runtime_component_health_transitions) to the client-facing
`OperationalEvent`. This is the ONE place titles/summaries/importance/
source-domain are decided — never in the browser.

Deliberately selective, not exhaustive: only "operationally
significant" execution event types are projected onto the cross-domain
Live Operations Feed / Security Change Feed (the brief explicitly warns
against flooding the feed with every internal step). The FULL,
unfiltered per-execution event list remains available via the
execution telemetry detail endpoint, which reads
validation_execution_events directly. An event type this registry
does not recognize is simply not projected (silence, never a crash,
never a fabricated entry) — see `project_execution_event()`'s
docstring.
"""

from __future__ import annotations

from redforge.domain.security_operations.operational_event import OperationalEvent
from redforge.domain.security_operations.value_objects import OperationalImportance, SourceDomain

# ─── Execution events ──────────────────────────────────────────────────────

_EXECUTION_EVENT_TITLES: dict[str, str] = {
    "execution_created": "Validation created",
    "execution_started": "Validation started",
    "policy_denied": "Validation blocked: authorization denied",
    "cancellation_requested": "Validation cancellation requested",
    "execution_cancelled": "Validation cancelled",
    "execution_completed": "Validation completed",
    "execution_partial": "Validation partially completed",
    "execution_failed": "Validation failed",
    "step_failed": "Validation step failed",
    "condition_ingested": "Security condition observed",
    "port_reachability_observed": "Port reachability observed",
}

_EXECUTION_EVENT_IMPORTANCE: dict[str, OperationalImportance] = {
    "execution_created": OperationalImportance.INFO,
    "execution_started": OperationalImportance.INFO,
    "policy_denied": OperationalImportance.WARNING,
    "cancellation_requested": OperationalImportance.NOTICE,
    "execution_cancelled": OperationalImportance.NOTICE,
    "execution_completed": OperationalImportance.INFO,
    "execution_partial": OperationalImportance.WARNING,
    "execution_failed": OperationalImportance.WARNING,
    "step_failed": OperationalImportance.WARNING,
    "condition_ingested": OperationalImportance.NOTICE,
    "port_reachability_observed": OperationalImportance.INFO,
}


def _execution_summary(event_type: str, payload: dict[str, str]) -> str:
    if event_type == "policy_denied":
        return f"Authorization denied ({payload.get('reason_code', 'unknown')})."
    if event_type == "step_failed":
        step_type = payload.get("step_type", "step")
        reason = payload.get("reason")
        return f"{step_type} failed" + (f" ({reason})." if reason else ".")
    if event_type == "condition_ingested":
        rule_id = payload.get("stable_rule_id", "unknown")
        port = payload.get("port")
        return f"Condition observed: {rule_id}" + (f" on port {port}." if port else ".")
    if event_type == "port_reachability_observed":
        ports = payload.get("reachable_ports", "")
        return f"Reachable ports: {ports}." if ports else "No ports reachable."
    return _EXECUTION_EVENT_TITLES.get(event_type, event_type) + "."


def project_execution_event(
    *, event_type: str, payload: dict[str, str], execution_id: str,
    organization_id: str, occurred_at: str,
) -> OperationalEvent | None:
    """Returns None for an execution event type this registry does not
    surface on the cross-domain feed (see module docstring) — the
    caller simply skips it, never substituting a fabricated entry."""
    if event_type not in _EXECUTION_EVENT_TITLES:
        return None
    return OperationalEvent(
        cursor="",
        event_id=f"validation:{execution_id}:{event_type}:{occurred_at}",
        organization_id=organization_id,
        source_domain=SourceDomain.VALIDATION,
        importance=_EXECUTION_EVENT_IMPORTANCE.get(event_type, OperationalImportance.INFO),
        title=_EXECUTION_EVENT_TITLES.get(event_type, event_type),
        summary=_execution_summary(event_type, payload),
        entity_type="validation_execution",
        entity_id=execution_id,
        occurred_at=occurred_at,
    )


# ─── Security drift events ─────────────────────────────────────────────────

_DRIFT_IMPORTANCE: dict[str, OperationalImportance] = {
    "condition_appeared": OperationalImportance.WARNING,
    "condition_reactivated": OperationalImportance.WARNING,
    "condition_resolved": OperationalImportance.NOTICE,
    "correlation_appeared": OperationalImportance.HIGH,
    "correlation_resolved": OperationalImportance.NOTICE,
    "tls_certificate_changed": OperationalImportance.WARNING,
    "protocol_no_longer_validated": OperationalImportance.WARNING,
    "port_no_longer_reachable": OperationalImportance.NOTICE,
}

_DRIFT_TITLES: dict[str, str] = {
    "ip_observed": "IP address observed",
    "ip_no_longer_observed": "IP address no longer observed",
    "port_became_reachable": "Port became reachable",
    "port_no_longer_reachable": "Port no longer reachable",
    "protocol_validated": "Protocol validated",
    "protocol_no_longer_validated": "Protocol no longer validated",
    "protocol_changed": "Protocol changed",
    "tls_certificate_changed": "TLS certificate changed",
    "condition_appeared": "Security condition appeared",
    "condition_resolved": "Security condition resolved",
    "condition_reactivated": "Security condition reactivated",
    "correlation_appeared": "Correlation appeared",
    "correlation_resolved": "Correlation resolved",
}


def project_drift_event(
    *, drift_event_id: str, category: str, summary: str, execution_id: str,
    continuous_policy_id: str, organization_id: str, occurred_at: str,
) -> OperationalEvent:
    return OperationalEvent(
        cursor="",
        event_id=f"drift:{drift_event_id}",
        organization_id=organization_id,
        source_domain=SourceDomain.SECURITY_DRIFT,
        importance=_DRIFT_IMPORTANCE.get(category, OperationalImportance.NOTICE),
        title=_DRIFT_TITLES.get(category, category),
        summary=summary,
        entity_type="continuous_validation_policy",
        entity_id=continuous_policy_id,
        occurred_at=occurred_at,
    )


# ─── Continuous validation policy lifecycle events ─────────────────────────

_POLICY_LIFECYCLE_TITLES: dict[str, str] = {
    "created": "Continuous validation policy created",
    "activated": "Continuous validation policy activated",
    "paused": "Continuous validation policy paused",
    "resumed": "Continuous validation policy resumed",
    "disabled": "Continuous validation policy disabled",
}


def project_policy_lifecycle_event(
    *, event_id: str, event_type: str, policy_id: str, organization_id: str, occurred_at: str,
) -> OperationalEvent:
    return OperationalEvent(
        cursor="",
        event_id=f"policy:{event_id}",
        organization_id=organization_id,
        source_domain=SourceDomain.CONTINUOUS_VALIDATION,
        importance=(
            OperationalImportance.WARNING
            if event_type == "disabled"
            else OperationalImportance.NOTICE
        ),
        title=_POLICY_LIFECYCLE_TITLES.get(event_type, event_type),
        summary=_POLICY_LIFECYCLE_TITLES.get(event_type, event_type) + ".",
        entity_type="continuous_validation_policy",
        entity_id=policy_id,
        occurred_at=occurred_at,
    )


# ─── Runtime health transitions ────────────────────────────────────────────


# ─── Network validation run events (M16) ───────────────────────────────────

_NETWORK_RUN_EVENT_TITLES: dict[str, str] = {
    "run_created": "Network validation created",
    "policy_denied": "Network validation blocked: authorization denied",
    "run_authorized": "Network validation authorized",
    "run_started": "Network validation started",
    "run_finished": "Network validation completed",
}

_NETWORK_RUN_EVENT_IMPORTANCE: dict[str, OperationalImportance] = {
    "run_created": OperationalImportance.INFO,
    "policy_denied": OperationalImportance.WARNING,
    "run_authorized": OperationalImportance.INFO,
    "run_started": OperationalImportance.INFO,
    "run_finished": OperationalImportance.INFO,
}


def _network_run_summary(event_type: str, payload: dict[str, str]) -> str:
    if event_type == "policy_denied":
        return f"Authorization denied ({payload.get('reason_code', 'unknown')})."
    if event_type == "run_finished":
        status = payload.get("status", "unknown")
        return f"Network validation run finished with status: {status}."
    return _NETWORK_RUN_EVENT_TITLES.get(event_type, event_type) + "."


def project_network_run_event(
    *, event_type: str, payload: dict[str, str], run_id: str,
    organization_id: str, occurred_at: str,
) -> OperationalEvent | None:
    """Returns None for a network run event type this registry does not
    surface on the cross-domain feed — the caller skips it, never
    substituting a fabricated entry."""
    if event_type not in _NETWORK_RUN_EVENT_TITLES:
        return None
    return OperationalEvent(
        cursor="",
        event_id=f"network_run:{run_id}:{event_type}:{occurred_at}",
        organization_id=organization_id,
        source_domain=SourceDomain.NETWORK_SECURITY,
        importance=_NETWORK_RUN_EVENT_IMPORTANCE.get(event_type, OperationalImportance.INFO),
        title=_NETWORK_RUN_EVENT_TITLES.get(event_type, event_type),
        summary=_network_run_summary(event_type, payload),
        entity_type="network_validation_run",
        entity_id=run_id,
        occurred_at=occurred_at,
    )


# ─── Network monitoring policy lifecycle events (M16) ──────────────────────

_NETWORK_POLICY_LIFECYCLE_TITLES: dict[str, str] = {
    "created": "Network monitoring policy created",
    "activated": "Network monitoring policy activated",
    "paused": "Network monitoring policy paused",
    "resumed": "Network monitoring policy resumed",
    "disabled": "Network monitoring policy disabled",
}


def project_network_policy_lifecycle_event(
    *, event_id: str, event_type: str, policy_id: str, organization_id: str, occurred_at: str,
) -> OperationalEvent:
    return OperationalEvent(
        cursor="",
        event_id=f"network_policy:{event_id}",
        organization_id=organization_id,
        source_domain=SourceDomain.NETWORK_SECURITY,
        importance=(
            OperationalImportance.WARNING
            if event_type == "disabled"
            else OperationalImportance.NOTICE
        ),
        title=_NETWORK_POLICY_LIFECYCLE_TITLES.get(event_type, event_type),
        summary=_NETWORK_POLICY_LIFECYCLE_TITLES.get(event_type, event_type) + ".",
        entity_type="network_monitoring_policy",
        entity_id=policy_id,
        occurred_at=occurred_at,
    )


def project_runtime_transition(
    *, transition_id: str, component_id: str, old_status: str, new_status: str,
    organization_id: str, occurred_at: str,
) -> OperationalEvent:
    importance = (
        OperationalImportance.HIGH if new_status == "unhealthy" else OperationalImportance.NOTICE
    )
    return OperationalEvent(
        cursor="",
        event_id=f"runtime:{transition_id}",
        organization_id=organization_id,
        source_domain=SourceDomain.RUNTIME,
        importance=importance,
        title=f"Runtime component {new_status}: {component_id}",
        summary=f"{component_id} transitioned {old_status} -> {new_status}.",
        entity_type="runtime_component",
        entity_id=component_id,
        occurred_at=occurred_at,
    )
