"""Canonical, versioned, bounded discovery port policy — M12.

This is the ONE port truth NETWORK_DISCOVERY_BASELINE_V1 reads from —
never a client-submitted port list, never an expansion to the full
1-65535 range. The policy is small and enterprise-relevant on purpose:
enough to trigger the adaptive HTTP/HTTPS validation rules and to
observe common remote-administration/database exposure, nothing more.

Ownership: this module owns "which ports does bounded discovery probe
and what hint does each port suggest" (`DISCOVERY_PORT_POLICY_V1`,
`expected_service_hint()`). It deliberately does NOT own "which
observed port is sensitive enough to become a SecurityCondition" — that
judgment already belongs to
`application/network_discovery/analysis_service.SENSITIVE_PORTS`
(M6), imported here unchanged so the two modules can never silently
diverge on what "sensitive" means.
"""

from __future__ import annotations

from redforge.application.network_discovery.analysis_service import SENSITIVE_PORTS

# M13 bumped 1->2: added port 6379 (redis) so the Redis protocol
# candidate can be discovered. Historical executions persisted their
# own `discovery_port_policy_version` in `ExecutionLimits` at run time —
# this bump never reinterprets a past execution's port list, it only
# changes what NEW executions probe.
DISCOVERY_PORT_POLICY_VERSION = 2

# Port -> EXPECTED_SERVICE_HINT. A hint is never a validated claim — see
# ServiceEvidenceState in domain/validation_execution/value_objects.py.
# Only ports with a real, implemented protocol-specific validator (see
# VALIDATABLE_PORTS / PROTOCOL_VALIDATOR_PORTS below) ever produce
# SERVICE_VALIDATED; every other port here tops out at SERVICE_HINTED.
DISCOVERY_PORT_HINTS: dict[int, str] = {
    22: "ssh",
    80: "http",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    6379: "redis",  # M13
    8080: "http-alt",
    8443: "https-alt",
}

DISCOVERY_PORT_POLICY_V1: tuple[int, ...] = tuple(sorted(DISCOVERY_PORT_HINTS))

# Ports whose real validators exist today (M11's TLS/HTTP adapters,
# adaptively scheduled by application/validation_execution/adaptive_rules.py).
VALIDATABLE_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})

# M13 — ports with a real, bounded, non-authenticating protocol
# validator (application/validation_execution/protocol_validators.py).
# 3389 (RDP) is deliberately NOT included: safely validating RDP
# without touching NLA/credential negotiation is not honestly provable
# with a bounded, non-authenticating probe this milestone — it stays
# SERVICE_HINTED, and this is a documented deferral, not an oversight.
PROTOCOL_VALIDATOR_PORTS: frozenset[int] = frozenset({22, 3306, 5432, 6379})


def expected_service_hint(port: int) -> str:
    """Never a banner-derived guess — only the well-known-port
    convention for the number itself. Unknown ports return "" rather
    than inventing a protocol."""
    return DISCOVERY_PORT_HINTS.get(port, "")


def is_sensitive_port(port: int) -> bool:
    """Delegates to M6's own sensitive-port judgment (`SENSITIVE_PORTS`)
    — never a second, divergent classification."""
    return port in SENSITIVE_PORTS


def sensitive_service_name(port: int) -> str:
    return SENSITIVE_PORTS.get(port, "")
