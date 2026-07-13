"""Condition reconciliation — M14.

Implements "rule ownership / revalidation coverage": only a
SecurityCondition rule whose covering step(s) genuinely completed
successfully IN THIS RUN is eligible to have its now-absent conditions
resolved. A condition for a rule whose covering step was skipped,
failed, timed out, cancelled, or — for protocol steps specifically —
merely reached HINTED/INCONCLUSIVE (not VALIDATED) must NEVER be
resolved on this run; the absence is inconclusive, not proof the
condition no longer holds.

This is the one deliberate exception carved into M8's original "explicit
resolution only" design — see
`TenantSecurityConditionService.resolve_stale_for_rule_and_asset()`'s own
docstring for why it is safe here specifically.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.application.validation_execution.execution_service import (
        StepDTO,
        ValidationExecutionDTO,
    )

# Which StepType(s) — by their DTO string value — constitute authoritative
# re-evaluation coverage for each condition rule this bounded context
# knows how to reconcile. Mirrors the stable_rule_id constants defined in
# application/validation_execution/network_adapters.py and
# execution_service.py exactly; intentionally duplicated as plain string
# literals here rather than imported, to keep this module import-light
# and free of any dependency on execution_service's private module state.
_CONDITION_RULE_COVERAGE: dict[str, frozenset[str]] = {
    "MISSING_HSTS_HEADER": frozenset({"http_security_headers"}),
    "MISSING_CSP_HEADER": frozenset({"http_security_headers"}),
    "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER": frozenset({"http_security_headers"}),
    "TLS_CERTIFICATE_EXPIRED": frozenset({"tls_handshake"}),
    "TLS_SELF_SIGNED_CERTIFICATE_OBSERVED": frozenset({"tls_handshake"}),
    "DEPRECATED_TLS_PROTOCOL_OBSERVED": frozenset({"tls_handshake"}),
    "SENSITIVE_SERVICE_OBSERVED": frozenset({"port_discovery"}),
    "PLAINTEXT_SENSITIVE_SERVICE_OBSERVED": frozenset({
        "ssh_banner", "mysql_handshake", "postgresql_handshake", "redis_ping",
    }),
}

# Step types whose coverage requires more than bare StepStatus.COMPLETED
# — a protocol step can complete "successfully" while only reaching
# HINTED/INCONCLUSIVE (e.g. the port replied, but not with this
# protocol's expected shape); only genuine VALIDATED counts as having
# actually re-checked the underlying fact.
_PROTOCOL_VALIDATED_STEP_TYPES = frozenset({
    "ssh_banner", "mysql_handshake", "postgresql_handshake", "redis_ping",
})

# Rules whose covering step types are each tied to a DIFFERENT port/
# asset (one SSH step only ever re-checks port 22's own asset, one
# MySQL step only port 3306's, etc.) — unlike the header/TLS/port-
# discovery rules below, "some covering step of this shape ran
# somewhere in the execution" is NOT enough to call a specific asset's
# condition re-checked; only the asset whose OWN port the successful
# step actually targeted is covered. See compute_covered_ports_by_rule().
_PORT_SCOPED_RULES = frozenset({"PLAINTEXT_SENSITIVE_SERVICE_OBSERVED"})


def _step_provides_coverage(step: StepDTO, covering_types: frozenset[str]) -> bool:
    if step.step_type not in covering_types or step.status != "completed":
        return False
    if step.step_type in _PROTOCOL_VALIDATED_STEP_TYPES:
        return step.protocol_validation_state == "validated"
    return True


def _parse_tcp_port_fact_ref(fact_ref: str | None) -> int | None:
    """Mirrors execution_service.py's own `_parse_tcp_port_fact_ref` —
    duplicated (matching snapshot_builder.py's own precedent for this
    exact helper) rather than imported, to keep this module free of any
    dependency on execution_service's private module state. Parses the
    `"tcp_port:{port}:reachable"` fact_ref shape every adaptive rule
    uses."""
    if not fact_ref:
        return None
    parts = fact_ref.split(":")
    if len(parts) != 3 or parts[0] != "tcp_port":
        return None
    try:
        return int(parts[1])
    except ValueError:
        return None


def compute_covered_rule_ids(execution: ValidationExecutionDTO) -> frozenset[str]:
    """Returns the stable_rule_ids eligible for absence-based resolution
    from this execution — i.e. whose covering step(s) genuinely
    completed (and, for protocol steps, genuinely validated) this run.
    A rule not in this set must never have any condition resolved on
    its behalf for this execution, no matter how "clean" the rest of
    the run looked.

    For a rule in `_PORT_SCOPED_RULES`, membership here means only that
    SOME asset was covered this run — callers MUST additionally consult
    `compute_covered_ports_by_rule()` before resolving a SPECIFIC
    asset's condition for that rule; being in this set alone is
    correct-but-insufficient for those rules (see that function's own
    docstring for the failure mode this guards against)."""
    covered: set[str] = set()
    for rule_id, covering_types in _CONDITION_RULE_COVERAGE.items():
        if any(_step_provides_coverage(step, covering_types) for step in execution.steps):
            covered.add(rule_id)
    return frozenset(covered)


def compute_covered_ports_by_rule(
    execution: ValidationExecutionDTO,
) -> dict[str, frozenset[int]]:
    """For each rule in `_PORT_SCOPED_RULES`, the exact set of ports
    whose covering step genuinely validated THIS run — e.g. if only
    port 22's ssh_banner step validated, port 3306's still-active
    PLAINTEXT_SENSITIVE_SERVICE_OBSERVED condition must NOT be resolved
    even though "some" covering step type for that rule_id ran
    somewhere in the execution. Without this, one validated protocol
    step anywhere in the plan would incorrectly authorize resolving
    every other port's condition for the same rule_id, even ports this
    run never re-examined at all."""
    result: dict[str, frozenset[int]] = {}
    for rule_id in _PORT_SCOPED_RULES:
        covering_types = _CONDITION_RULE_COVERAGE.get(rule_id, frozenset())
        ports = {
            port
            for step in execution.steps
            if _step_provides_coverage(step, covering_types)
            and (port := _parse_tcp_port_fact_ref(step.source_fact_ref)) is not None
        }
        result[rule_id] = frozenset(ports)
    return result


def known_condition_rule_ids() -> frozenset[str]:
    """The closed set of stable_rule_ids this bounded context knows how
    to reconcile. A condition whose rule is not in this set (e.g. a
    future rule added without updating the coverage map) is never
    touched by absence-based resolution — silence, not a crash, and
    never a false resolution."""
    return frozenset(_CONDITION_RULE_COVERAGE.keys())
