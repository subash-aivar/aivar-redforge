"""Drift detector — M14.

Pure functions comparing two ValidationStateSnapshots and producing
SecurityDriftEvent domain entities. No I/O, no persistence, no network
— exactly the comparison boundary ValidationStateSnapshot itself
defines (see its own docstring). Identical canonical state (proven via
`ValidationStateSnapshot.is_identical_to()`'s fast-path fingerprint
check) MUST produce zero drift events; this module's entry point
enforces that as its very first check.

No class named `DriftDetector` — deliberately avoiding a collision with
the unrelated, unwired `domain.posture.DriftDetector` (LLM attack-result
drift, a different concept entirely). See
domain/continuous_validation/value_objects.py's own module docstring.

CONDITION_REACTIVATED is intentionally NOT computed by this module —
distinguishing a fresh CONDITION_APPEARED from a genuine reactivation of
a previously-resolved condition requires the condition's own
`first_observed_at` (proof the row already existed before the previous
snapshot), which this module has no access to (it only ever sees
snapshot-level identity keys, never per-condition timestamps). The
caller (the continuous validation processor) computes
`reactivated_condition_keys` from that timestamp and passes it in; this
module only ever honors that pre-computed classification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.continuous_validation.entity import SecurityDriftEvent, ServiceSnapshotEntry
from redforge.domain.continuous_validation.value_objects import SecurityDriftCategory

if TYPE_CHECKING:
    from redforge.domain.continuous_validation.entity import ValidationStateSnapshot
    from redforge.shared.identifiers import EntityId


def _drift(
    organization_id: EntityId,
    continuous_policy_id: EntityId,
    execution_id: EntityId,
    category: SecurityDriftCategory,
    identity_key: str,
    summary: str,
) -> SecurityDriftEvent:
    return SecurityDriftEvent.create(
        organization_id=organization_id,
        continuous_policy_id=continuous_policy_id,
        execution_id=execution_id,
        category=category,
        identity_key=identity_key,
        summary=summary,
    )


def detect_drift(
    previous: ValidationStateSnapshot | None,
    current: ValidationStateSnapshot,
    organization_id: EntityId,
    continuous_policy_id: EntityId,
    execution_id: EntityId,
    reactivated_condition_keys: frozenset[str] = frozenset(),
) -> list[SecurityDriftEvent]:
    """Compare `previous` (the prior canonical snapshot for this policy,
    or None on the very first run) against `current`. Returns an empty
    list when nothing genuinely changed — never fabricated drift for a
    policy's first-ever run (there is no baseline to differ against,
    so nothing is reported, not "everything appeared")."""
    if previous is None:
        return []
    if previous.is_identical_to(current):
        return []

    events: list[SecurityDriftEvent] = []

    prev_ips = set(previous.resolved_ips)
    curr_ips = set(current.resolved_ips)
    for ip in sorted(curr_ips - prev_ips):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.IP_OBSERVED, f"ip:{ip}", f"IP address {ip} newly observed.",
        ))
    for ip in sorted(prev_ips - curr_ips):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.IP_NO_LONGER_OBSERVED, f"ip:{ip}",
            f"IP address {ip} no longer observed.",
        ))

    prev_ports = set(previous.reachable_ports)
    curr_ports = set(current.reachable_ports)
    for port in sorted(curr_ports - prev_ports):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.PORT_BECAME_REACHABLE, f"port:{port}",
            f"Port {port} became reachable.",
        ))
    for port in sorted(prev_ports - curr_ports):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.PORT_NO_LONGER_REACHABLE, f"port:{port}",
            f"Port {port} is no longer reachable.",
        ))

    prev_services = {s.port: s for s in previous.services}
    curr_services = {s.port: s for s in current.services}
    for port in sorted(set(prev_services) | set(curr_services)):
        prev_svc = prev_services.get(port)
        curr_svc = curr_services.get(port)
        events.extend(_service_drift(
            organization_id, continuous_policy_id, execution_id, port, prev_svc, curr_svc,
        ))

    prev_conditions = set(previous.active_condition_keys)
    curr_conditions = set(current.active_condition_keys)
    for key in sorted(curr_conditions - prev_conditions):
        category = (
            SecurityDriftCategory.CONDITION_REACTIVATED
            if key in reactivated_condition_keys
            else SecurityDriftCategory.CONDITION_APPEARED
        )
        verb = "reactivated" if key in reactivated_condition_keys else "appeared"
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id, category, key,
            f"Security condition {verb}: {key}.",
        ))
    for key in sorted(prev_conditions - curr_conditions):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.CONDITION_RESOLVED, key, f"Security condition resolved: {key}.",
        ))

    prev_correlations = set(previous.active_correlation_keys)
    curr_correlations = set(current.active_correlation_keys)
    for key in sorted(curr_correlations - prev_correlations):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.CORRELATION_APPEARED, key, f"Correlation appeared: {key}.",
        ))
    for key in sorted(prev_correlations - curr_correlations):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.CORRELATION_RESOLVED, key, f"Correlation resolved: {key}.",
        ))

    return events


def _service_drift(
    organization_id: EntityId,
    continuous_policy_id: EntityId,
    execution_id: EntityId,
    port: int,
    prev: ServiceSnapshotEntry | None,
    curr: ServiceSnapshotEntry | None,
) -> list[SecurityDriftEvent]:
    events: list[SecurityDriftEvent] = []

    prev_protocol = prev.validated_protocol if prev else None
    curr_protocol = curr.validated_protocol if curr else None

    if prev_protocol is None and curr_protocol is not None:
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.PROTOCOL_VALIDATED, f"port:{port}",
            f"Port {port} protocol validated as {curr_protocol}.",
        ))
    elif prev_protocol is not None and curr_protocol is None:
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.PROTOCOL_NO_LONGER_VALIDATED, f"port:{port}",
            f"Port {port} no longer validates as {prev_protocol}.",
        ))
    elif (
        prev_protocol is not None
        and curr_protocol is not None
        and prev_protocol != curr_protocol
    ):
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.PROTOCOL_CHANGED, f"port:{port}",
            f"Port {port} protocol changed from {prev_protocol} to {curr_protocol}.",
        ))

    # TLS certificate drift only when BOTH sides genuinely validated TLS
    # — never inferred from one side being absent (a service that
    # simply stopped speaking TLS is PROTOCOL_NO_LONGER_VALIDATED, not a
    # certificate change).
    prev_fp = prev.tls_fingerprint_sha256 if prev else None
    curr_fp = curr.tls_fingerprint_sha256 if curr else None
    if prev_fp is not None and curr_fp is not None and prev_fp != curr_fp:
        events.append(_drift(
            organization_id, continuous_policy_id, execution_id,
            SecurityDriftCategory.TLS_CERTIFICATE_CHANGED, f"port:{port}",
            f"TLS certificate fingerprint changed on port {port}.",
        ))

    return events
