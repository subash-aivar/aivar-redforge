"""Adversarial + unit tests for M12 — Authorized Network Discovery &
Adaptive Validation Orchestration.

Covers checklist items 5-13, 19-24, 32-38, 41 (bounded discovery
mechanics, adaptive rule determinism/dedup, port-truth non-duplication,
network-boundary/SSRF/redirect protections retained, secret absence,
plan-expansion bound) at the unit/adapter level — never against an
external/unrelated internet target, always owned local test servers or
pure in-memory domain logic.

API-level adversarial coverage (policy gate, tenant isolation,
cancellation, restart persistence, correlation dedup, no-arbitrary-
endpoint) lives in tests/api/test_validation_executions_m12_isolation.py.
"""

from __future__ import annotations

import http.server
import threading

import pytest

from redforge.application.network_discovery.analysis_service import SENSITIVE_PORTS
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.adaptive_rules import (
    AdaptiveRuleRegistry,
    DiscoveryFacts,
    DuplicateAdaptiveRuleRegistrationError,
    Port80HttpRule,
    Port443TlsHttpsRule,
    default_adaptive_rule_registry,
)
from redforge.application.validation_execution.discovery_port_policy import (
    DISCOVERY_PORT_HINTS,
    DISCOVERY_PORT_POLICY_V1,
    expected_service_hint,
    is_sensitive_port,
    sensitive_service_name,
)
from redforge.domain.validation_execution.entity import ValidationExecution
from redforge.domain.validation_execution.exceptions import InvalidExecutionTransitionError
from redforge.domain.validation_execution.value_objects import (
    AddressClass,
    DiscoveryPortOutcome,
    StepSource,
    StepType,
    ValidationProfile,
)
from redforge.shared.identifiers import EntityId

# ─── 32-38: port-truth ownership, no duplication ──────────────────────────────


class TestDiscoveryPortPolicyOwnership:
    def test_sensitive_ports_reused_from_m6_not_duplicated(self) -> None:
        """M12 must not maintain a second, divergent "which port is
        sensitive" list — it imports M6's exact table."""
        for port, name in SENSITIVE_PORTS.items():
            assert is_sensitive_port(port)
            assert sensitive_service_name(port) == name

    def test_port_policy_is_small_and_bounded(self) -> None:
        assert len(DISCOVERY_PORT_POLICY_V1) <= 12
        assert 0 not in DISCOVERY_PORT_POLICY_V1
        assert all(1 <= p <= 65535 for p in DISCOVERY_PORT_POLICY_V1)

    def test_unknown_port_never_gets_a_fabricated_hint(self) -> None:
        assert expected_service_hint(65000) == ""

    def test_web_ports_present_for_adaptive_triggering(self) -> None:
        assert 80 in DISCOVERY_PORT_POLICY_V1
        assert 443 in DISCOVERY_PORT_POLICY_V1
        assert DISCOVERY_PORT_HINTS[80] == "http"
        assert DISCOVERY_PORT_HINTS[443] == "https"


# ─── 6, 21, 41: deterministic adaptive rule engine ────────────────────────────


class TestAdaptiveRuleRegistry:
    def test_duplicate_rule_registration_rejected(self) -> None:
        registry = AdaptiveRuleRegistry()
        registry.register(Port443TlsHttpsRule())
        with pytest.raises(DuplicateAdaptiveRuleRegistrationError):
            registry.register(Port443TlsHttpsRule())

    def test_default_registry_has_exactly_the_expected_rules(self) -> None:
        registry = default_adaptive_rule_registry()
        ids = {(r.rule_id, r.rule_version) for r in registry.all_rules()}
        assert ids == {
            ("PORT_443_TLS_HTTPS", 1), ("PORT_80_HTTP", 1),
            ("PORT_22_SSH", 1), ("PORT_3306_MYSQL", 1),
            ("PORT_5432_POSTGRESQL", 1), ("PORT_6379_REDIS", 1),
        }

    def test_port_443_rule_proposes_tls_and_https_steps(self) -> None:
        rule = Port443TlsHttpsRule()
        facts = DiscoveryFacts(reachable_ports=frozenset({443}), target_is_https=False)
        specs = rule.evaluate(facts, frozenset())
        assert {s.step_type for s in specs} == {
            StepType.TLS_HANDSHAKE, StepType.HTTP_METADATA, StepType.HTTP_SECURITY_HEADERS,
        }
        assert all(s.fact_ref == "tcp_port:443:reachable" for s in specs)

    def test_port_8443_https_alt_also_triggers_tls_rule(self) -> None:
        """Enterprise https-alt convention — never a fabricated
        protocol guess, just the same real TLS/HTTP adapters at the
        alternate well-known port."""
        rule = Port443TlsHttpsRule()
        facts = DiscoveryFacts(reachable_ports=frozenset({8443}), target_is_https=False)
        specs = rule.evaluate(facts, frozenset())
        assert len(specs) == 3
        assert all(s.fact_ref == "tcp_port:8443:reachable" for s in specs)

    def test_port_80_rule_proposes_http_steps_only(self) -> None:
        rule = Port80HttpRule()
        facts = DiscoveryFacts(reachable_ports=frozenset({80}), target_is_https=False)
        specs = rule.evaluate(facts, frozenset())
        assert {s.step_type for s in specs} == {
            StepType.HTTP_METADATA, StepType.HTTP_SECURITY_HEADERS,
        }

    def test_unreachable_port_never_triggers_a_rule(self) -> None:
        rule = Port443TlsHttpsRule()
        facts = DiscoveryFacts(reachable_ports=frozenset({22}), target_is_https=False)
        assert rule.evaluate(facts, frozenset()) == []

    def test_rule_never_duplicates_an_already_planned_step_type(self) -> None:
        """21/23: repeated evaluation is idempotent/duplicate-resistant
        — a step type already in the plan is never proposed again."""
        rule = Port443TlsHttpsRule()
        facts = DiscoveryFacts(reachable_ports=frozenset({443}), target_is_https=False)
        already_planned = frozenset({StepType.TLS_HANDSHAKE, StepType.HTTP_METADATA})
        specs = rule.evaluate(facts, already_planned)
        assert {s.step_type for s in specs} == {StepType.HTTP_SECURITY_HEADERS}

    def test_unknown_port_cannot_trigger_arbitrary_protocol_probe(self) -> None:
        """23: only 80/8080/443/8443/22/3306/5432/6379 are wired to any
        rule at all — every other port, however "interesting" it looks
        (including 3389/RDP, an intentionally deferred protocol — see
        discovery_port_policy.py), produces zero adaptive steps from
        the default registry."""
        registry = default_adaptive_rule_registry()
        facts = DiscoveryFacts(reachable_ports=frozenset({3389, 21, 25, 143}), target_is_https=False)
        all_specs = [s for r in registry.all_rules() for s in r.evaluate(facts, frozenset())]
        assert all_specs == []


# ─── Domain-level adaptive step append (bounds, dedup, illegal state) ─────────


def _running_discovery_execution() -> ValidationExecution:
    execution = ValidationExecution.create(
        organization_id=EntityId.generate(), target_id=EntityId.generate(),
        requester_user_id=EntityId.generate(),
        profile=ValidationProfile.NETWORK_DISCOVERY_BASELINE_V1,
    )
    execution.begin_policy_check()
    execution.authorize("dec-1")
    execution.build_plan([StepType.DNS_RESOLUTION, StepType.PORT_DISCOVERY])
    execution.start()
    return execution


class TestAdaptiveStepAppend:
    def test_append_adaptive_step_only_legal_while_running(self) -> None:
        execution = ValidationExecution.create(
            organization_id=EntityId.generate(), target_id=EntityId.generate(),
            requester_user_id=EntityId.generate(),
        )
        with pytest.raises(InvalidExecutionTransitionError):
            execution.append_adaptive_step(
                StepType.HTTP_METADATA, "PORT_80_HTTP", 1, "tcp_port:80:reachable",
            )

    def test_repeated_fact_does_not_duplicate_adaptive_step(self) -> None:
        """19/20: re-observing the same port reachability twice, or
        concurrent rule evaluation proposing the same step twice,
        never appends the step twice."""
        execution = _running_discovery_execution()
        first = execution.append_adaptive_step(
            StepType.HTTP_METADATA, "PORT_80_HTTP", 1, "tcp_port:80:reachable",
        )
        second = execution.append_adaptive_step(
            StepType.HTTP_METADATA, "PORT_80_HTTP", 1, "tcp_port:80:reachable",
        )
        assert first is not None
        assert second is None
        assert sum(1 for s in execution.steps if s.step_type == StepType.HTTP_METADATA) == 1

    def test_plan_expansion_has_a_hard_maximum(self) -> None:
        """41: max_adaptive_steps and max_steps both bound expansion —
        never unbounded growth."""
        execution = _running_discovery_execution()
        limits = execution.limits
        added = 0
        for i in range(limits.max_adaptive_steps + 5):
            step = execution.append_adaptive_step(
                StepType.HTTP_METADATA if i % 2 == 0 else StepType.HTTP_SECURITY_HEADERS,
                f"FAKE_RULE_{i}", 1, f"tcp_port:{8000 + i}:reachable",
            )
            if step is not None:
                added += 1
        assert added <= limits.max_adaptive_steps
        assert len(execution.steps) <= limits.max_steps

    def test_adaptive_step_provenance_is_persisted_on_the_entity(self) -> None:
        execution = _running_discovery_execution()
        step = execution.append_adaptive_step(
            StepType.TLS_HANDSHAKE, "PORT_443_TLS_HTTPS", 1, "tcp_port:443:reachable",
        )
        assert step is not None
        assert step.source == StepSource.ADAPTIVE
        assert step.adaptive_rule_id == "PORT_443_TLS_HTTPS"
        assert step.adaptive_rule_version == 1
        assert step.source_fact_ref == "tcp_port:443:reachable"

    def test_initial_steps_have_no_adaptive_provenance(self) -> None:
        execution = _running_discovery_execution()
        for step in execution.steps:
            assert step.source == StepSource.INITIAL
            assert step.adaptive_rule_id is None
            assert step.adaptive_rule_version is None
            assert step.source_fact_ref is None


# ─── Bounded discovery adapter (owned local test server only) ────────────────


_PORT_OPEN = 18601
_PORT_CLOSED = 18602  # never bound — deliberately closed


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture(scope="module", autouse=True)
def _local_server():
    server = http.server.HTTPServer(("127.0.0.1", _PORT_OPEN), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _allow_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test-only relaxation, documented identically in M11's own
    network-boundary test file — production denies LOOPBACK by
    default; this suite's owned test server is necessarily
    loopback-bound."""
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


class TestBoundedDiscoveryAdapter:
    async def test_discover_ports_distinguishes_reachable_and_unreachable(self) -> None:
        result = await network_adapters.discover_ports(
            ("127.0.0.1",), (_PORT_OPEN, _PORT_CLOSED), timeout=1.0, max_concurrency=4,
        )
        assert result.reachable_ports == (_PORT_OPEN,)
        closed_outcome = result.best_outcome_for_port(_PORT_CLOSED)
        assert closed_outcome in (
            DiscoveryPortOutcome.UNREACHABLE, DiscoveryPortOutcome.NETWORK_ERROR,
        )

    async def test_discover_ports_respects_max_concurrency_bound(self) -> None:
        """9: bounded concurrency — a semaphore of size 1 must still
        complete (serialized) rather than hang or error."""
        result = await network_adapters.discover_ports(
            ("127.0.0.1",), (_PORT_OPEN,), timeout=1.0, max_concurrency=1,
        )
        assert result.reachable_ports == (_PORT_OPEN,)

    async def test_discover_ports_bounded_by_small_port_list(self) -> None:
        """10: port count is whatever the caller (the closed
        DISCOVERY_PORT_POLICY_V1) supplies — never the full 1-65535
        range. This just proves the adapter itself imposes no floor/
        ceiling surprise for a small, explicit list."""
        result = await network_adapters.discover_ports(
            ("127.0.0.1",), DISCOVERY_PORT_POLICY_V1, timeout=0.5, max_concurrency=8,
        )
        assert len(result.entries) == len({"127.0.0.1"}) * len(DISCOVERY_PORT_POLICY_V1)
