"""Deterministic, versioned adaptive validation-plan rule registry —
M12, extended with protocol-candidate rules in M13.

Mirrors `application/security_correlation/rules.py`'s
`CorrelationRuleRegistry` pattern exactly: plain Python objects register
by `(rule_id, rule_version)`, duplicates rejected, no arbitrary
expressions, no browser input, no LLM-generated predicates. Every rule
is a hand-written class reading only a small, closed `DiscoveryFacts`
snapshot and proposing steps from the SAME closed `StepType` taxonomy
M11/M13 already established — a rule can never invent a new step type
or protocol probe.

ADAPTIVE RULES CAN ONLY SELECT PRE-REGISTERED SAFE STEP TYPES — this is
enforced structurally: `AdaptiveStepSpec.step_type` is a `StepType`
enum member, and every step type in this module already has a real
adapter (`network_adapters.py` for M11/M12, `protocol_validators.py`
for M13) wired into
`execution_service.ValidationExecutionService._run_steps()`. There is
no path from a rule to an arbitrary protocol probe.

A reachable port only ever creates a PROTOCOL CANDIDATE here (one
adaptive step gets scheduled) — it is never treated as validated
service identity; that distinction is made by the validator itself
(`ProtocolValidationState`), not by this registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from redforge.domain.validation_execution.value_objects import StepType


@dataclass(frozen=True, slots=True)
class DiscoveryFacts:
    """The closed set of canonical facts adaptive rules may read. Adding
    a new fact requires a deliberate change here — a rule can never read
    arbitrary execution/step state."""

    reachable_ports: frozenset[int]
    target_is_https: bool


@dataclass(frozen=True, slots=True)
class AdaptiveStepSpec:
    step_type: StepType
    fact_ref: str


@runtime_checkable
class AdaptiveRule(Protocol):
    rule_id: str
    rule_version: int

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]: ...


class DuplicateAdaptiveRuleRegistrationError(ValueError):
    pass


class Port443TlsHttpsRule:
    """REACHABLE TCP 443 (or the 8443 https-alt enterprise convention)
    -> TLS_HANDSHAKE, HTTPS HTTP_METADATA, HTTP_SECURITY_HEADERS. Never
    duplicates a step type the initial plan (or a prior adaptive round)
    already scheduled — e.g. an HTTPS-URL target validated under
    SAFE_ACTIVE_BASELINE_V1 already has these; this rule only ever
    fires for NETWORK_DISCOVERY_BASELINE_V1's initial
    DNS+PORT_DISCOVERY-only plan. Fires at most once per discovery
    round even if BOTH 443 and 8443 are reachable — the fact_ref always
    names whichever port is checked first in `_TRIGGER_PORTS`."""

    rule_id = "PORT_443_TLS_HTTPS"
    rule_version = 1
    _TRIGGER_PORTS = (443, 8443)

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]:
        triggered = next((p for p in self._TRIGGER_PORTS if p in facts.reachable_ports), None)
        if triggered is None:
            return []
        fact_ref = f"tcp_port:{triggered}:reachable"
        wanted = (StepType.TLS_HANDSHAKE, StepType.HTTP_METADATA, StepType.HTTP_SECURITY_HEADERS)
        return [
            AdaptiveStepSpec(step_type=st, fact_ref=fact_ref)
            for st in wanted
            if st not in existing_step_types
        ]


class Port80HttpRule:
    """REACHABLE TCP 80 (or the 8080 http-alt enterprise convention) ->
    HTTP_METADATA, HTTP_SECURITY_HEADERS."""

    rule_id = "PORT_80_HTTP"
    rule_version = 1
    _TRIGGER_PORTS = (80, 8080)

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]:
        triggered = next((p for p in self._TRIGGER_PORTS if p in facts.reachable_ports), None)
        if triggered is None:
            return []
        fact_ref = f"tcp_port:{triggered}:reachable"
        wanted = (StepType.HTTP_METADATA, StepType.HTTP_SECURITY_HEADERS)
        return [
            AdaptiveStepSpec(step_type=st, fact_ref=fact_ref)
            for st in wanted
            if st not in existing_step_types
        ]


class Port22SshRule:
    """M13 — REACHABLE TCP 22 -> SSH_BANNER. Each protocol-candidate
    rule below owns exactly one fixed port and one distinct `rule_id` —
    deliberately NOT a single generic "any sensitive port" rule, since
    `ValidationExecution.append_adaptive_step()`'s dedup key is
    `(step_type, adaptive_rule_id)`: a rule that fired the same step
    type for two different ports under one rule_id would silently drop
    the second occurrence. One port per rule sidesteps that entirely."""

    rule_id = "PORT_22_SSH"
    rule_version = 1
    _TRIGGER_PORT = 22

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]:
        if self._TRIGGER_PORT not in facts.reachable_ports:
            return []
        if StepType.SSH_BANNER in existing_step_types:
            return []
        return [AdaptiveStepSpec(
            step_type=StepType.SSH_BANNER, fact_ref=f"tcp_port:{self._TRIGGER_PORT}:reachable",
        )]


class Port3306MySqlRule:
    """M13 — REACHABLE TCP 3306 -> MYSQL_HANDSHAKE."""

    rule_id = "PORT_3306_MYSQL"
    rule_version = 1
    _TRIGGER_PORT = 3306

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]:
        if self._TRIGGER_PORT not in facts.reachable_ports:
            return []
        if StepType.MYSQL_HANDSHAKE in existing_step_types:
            return []
        return [AdaptiveStepSpec(
            step_type=StepType.MYSQL_HANDSHAKE, fact_ref=f"tcp_port:{self._TRIGGER_PORT}:reachable",
        )]


class Port5432PostgreSqlRule:
    """M13 — REACHABLE TCP 5432 -> POSTGRESQL_HANDSHAKE."""

    rule_id = "PORT_5432_POSTGRESQL"
    rule_version = 1
    _TRIGGER_PORT = 5432

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]:
        if self._TRIGGER_PORT not in facts.reachable_ports:
            return []
        if StepType.POSTGRESQL_HANDSHAKE in existing_step_types:
            return []
        return [AdaptiveStepSpec(
            step_type=StepType.POSTGRESQL_HANDSHAKE,
            fact_ref=f"tcp_port:{self._TRIGGER_PORT}:reachable",
        )]


class Port6379RedisRule:
    """M13 — REACHABLE TCP 6379 -> REDIS_PING."""

    rule_id = "PORT_6379_REDIS"
    rule_version = 1
    _TRIGGER_PORT = 6379

    def evaluate(
        self, facts: DiscoveryFacts, existing_step_types: frozenset[StepType],
    ) -> list[AdaptiveStepSpec]:
        if self._TRIGGER_PORT not in facts.reachable_ports:
            return []
        if StepType.REDIS_PING in existing_step_types:
            return []
        return [AdaptiveStepSpec(
            step_type=StepType.REDIS_PING, fact_ref=f"tcp_port:{self._TRIGGER_PORT}:reachable",
        )]


class AdaptiveRuleRegistry:
    """Closed, server-controlled registry. `register()` raises on a
    duplicate (rule_id, rule_version) — the exact same collision
    discipline `CorrelationRuleRegistry` uses (M9)."""

    def __init__(self) -> None:
        self._rules: dict[tuple[str, int], AdaptiveRule] = {}

    def register(self, rule: AdaptiveRule) -> None:
        key = (rule.rule_id, rule.rule_version)
        if key in self._rules:
            raise DuplicateAdaptiveRuleRegistrationError(
                f"Adaptive rule already registered: {rule.rule_id} v{rule.rule_version}"
            )
        self._rules[key] = rule

    def all_rules(self) -> list[AdaptiveRule]:
        return list(self._rules.values())

    def get(self, rule_id: str, rule_version: int) -> AdaptiveRule | None:
        return self._rules.get((rule_id, rule_version))


def default_adaptive_rule_registry() -> AdaptiveRuleRegistry:
    registry = AdaptiveRuleRegistry()
    registry.register(Port443TlsHttpsRule())
    registry.register(Port80HttpRule())
    registry.register(Port22SshRule())
    registry.register(Port3306MySqlRule())
    registry.register(Port5432PostgreSqlRule())
    registry.register(Port6379RedisRule())
    return registry
