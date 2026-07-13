"""Snapshot builder — M14.

Pure functions projecting one ValidationExecutionDTO into a normalized
ValidationStateSnapshot. This IS the comparison boundary drift detection
reads from — never a diff of raw execution JSON (see
ValidationStateSnapshot's own docstring). Excludes every volatile field
(observed_at, execution id, event id, latency, ordering, transient
exception text) by construction: none of those are read here at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.domain.continuous_validation.entity import (
    ServiceSnapshotEntry,
    ValidationStateSnapshot,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.application.validation_execution.execution_service import (
        StepDTO,
        ValidationExecutionDTO,
    )

_PROTOCOL_STEP_TYPES = frozenset({
    "ssh_banner", "mysql_handshake", "postgresql_handshake", "redis_ping",
})


def _parse_tcp_port_fact_ref(fact_ref: str | None) -> int | None:
    """Mirrors execution_service.py's own `_parse_tcp_port_fact_ref` —
    duplicated rather than imported to keep this module import-light
    and independent of execution_service's private helpers; the
    `"tcp_port:{port}:reachable"` shape is a stable, documented
    adaptive-rule convention, not an implementation detail likely to
    drift silently out of sync."""
    if not fact_ref:
        return None
    parts = fact_ref.split(":")
    if len(parts) != 3 or parts[0] != "tcp_port":
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def _reachable_ports_from_evidence(steps: list[StepDTO]) -> list[int]:
    ports: list[int] = []
    for step in steps:
        if step.step_type != "port_discovery" or step.status != "completed":
            continue
        for entry in step.evidence:
            label = entry.get("label", "")
            if not label.startswith("port_"):
                continue
            value = entry.get("value", "")
            if value.startswith("reachable"):
                try:
                    ports.append(int(label[len("port_") :]))
                except ValueError:
                    continue
    return ports


def _resolved_ips_from_evidence(steps: list[StepDTO]) -> list[str]:
    for step in steps:
        if step.step_type != "dns_resolution" or step.status != "completed":
            continue
        for entry in step.evidence:
            if entry.get("label") == "resolved_addresses":
                value = entry.get("value", "")
                return [ip for ip in value.split(",") if ip]
    return []


def _service_entry_for_step(step: StepDTO, target_port: int) -> ServiceSnapshotEntry | None:
    if step.status != "completed":
        return None

    if step.step_type in _PROTOCOL_STEP_TYPES:
        if step.protocol_validation_state != "validated":
            return None
        port = _parse_tcp_port_fact_ref(step.source_fact_ref) or target_port
        protocol = step.step_type.removesuffix("_banner").removesuffix("_handshake").removesuffix(
            "_ping",
        )
        return ServiceSnapshotEntry(
            port=port, validated_protocol=protocol,
            validator_id=step.validator_id, tls_fingerprint_sha256=None,
        )

    if step.step_type == "tls_handshake":
        fingerprint = next(
            (e["value"] for e in step.evidence if e.get("label") == "fingerprint_sha256"), None,
        )
        port = _parse_tcp_port_fact_ref(step.source_fact_ref) or target_port
        return ServiceSnapshotEntry(
            port=port, validated_protocol="tls", validator_id=None,
            tls_fingerprint_sha256=fingerprint,
        )

    if step.step_type == "http_metadata":
        port = _parse_tcp_port_fact_ref(step.source_fact_ref) or target_port
        return ServiceSnapshotEntry(
            port=port, validated_protocol="http", validator_id=None, tls_fingerprint_sha256=None,
        )

    return None


def build_snapshot_from_execution(
    execution: ValidationExecutionDTO,
    organization_id: EntityId,
    continuous_policy_id: EntityId,
    target_port: int,
    active_condition_keys: list[str],
    active_correlation_keys: list[str],
) -> ValidationStateSnapshot:
    resolved_ips = _resolved_ips_from_evidence(execution.steps)
    reachable_ports = _reachable_ports_from_evidence(execution.steps)
    services = [
        entry
        for step in execution.steps
        if (entry := _service_entry_for_step(step, target_port)) is not None
    ]

    return ValidationStateSnapshot.build(
        organization_id=organization_id,
        continuous_policy_id=continuous_policy_id,
        execution_id=EntityId.from_string(execution.id),
        resolved_ips=resolved_ips,
        reachable_ports=reachable_ports,
        services=services,
        active_condition_keys=active_condition_keys,
        active_correlation_keys=active_correlation_keys,
    )
