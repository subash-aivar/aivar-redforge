"""Bounded, typed network validation planner — M16.

Turns (authorized target asset, profile, previously-known services)
into a concrete, bounded plan: which ports to check against which
authorized addresses. Never accepts a client-supplied port list,
scanner flag, or command string — the ONLY client input is a
`NetworkValidationProfile` enum value (see domain/network_security/
value_objects.py).

No step here ever executes: EXECUTE_COMMAND / RUN_SCRIPT / RUN_MODULE /
RUN_EXPLOIT do not exist as PlanStepType members and never will (closed
enum, see value_objects.py).
"""

from __future__ import annotations

from dataclasses import dataclass

from redforge.domain.network_security.value_objects import NetworkValidationProfile

# Reuses the exact same deterministic, IANA-convention-derived port table
# M6's BoundedNetworkScanAdapter already uses — never a second,
# competing "well-known port" guess table.
_COMMON_SERVICE_PORTS: tuple[int, ...] = (22, 80, 443, 3306, 5432, 6379)

# NETWORK_DEEP_SAFE adds a small, fixed, still-bounded extended set —
# NOT 1-65535. Full-port scanning is explicitly out of scope for M16
# (see this module's own docstring and the M16 brief §11).
_EXTENDED_SERVICE_PORTS: tuple[int, ...] = (21, 23, 445, 1433, 3389, 8080, 8443, 27017)

MAX_PORTS_PER_PLAN = 20


@dataclass(frozen=True, slots=True)
class NetworkValidationPlan:
    """A concrete, bounded plan for one NetworkValidationRun.
    `addresses` has already passed both bounded-CIDR-expansion
    (domain/network_security/address.py) and per-address authorization
    (application/network_security/authorization_scope.py) by the time
    this is built — the planner itself decides ports only, never
    addresses/scope."""

    addresses: tuple[str, ...]
    ports: tuple[int, ...]
    profile: NetworkValidationProfile


def build_plan(
    profile: NetworkValidationProfile,
    authorized_addresses: tuple[str, ...],
    previously_known_ports: tuple[int, ...] = (),
) -> NetworkValidationPlan:
    """Deterministic, server-controlled port selection per profile:

    - NETWORK_BASELINE: previously-known ports ONLY. No new discovery.
      An address with no prior known service produces an empty port
      set for this run (never fabricated).
    - NETWORK_STANDARD: previously-known ports UNION the fixed common-
      service port set.
    - NETWORK_DEEP_SAFE: NETWORK_STANDARD's set UNION the fixed
      extended port set.

    The resulting port set is always bounded to MAX_PORTS_PER_PLAN
    (deterministic: lowest port numbers first) — this is a server-side
    safety bound, not a client-supplied limit.
    """
    known = tuple(sorted(set(previously_known_ports)))

    if profile == NetworkValidationProfile.NETWORK_BASELINE:
        ports = set(known)
    elif profile == NetworkValidationProfile.NETWORK_STANDARD:
        ports = set(known) | set(_COMMON_SERVICE_PORTS)
    else:
        ports = set(known) | set(_COMMON_SERVICE_PORTS) | set(_EXTENDED_SERVICE_PORTS)

    bounded_ports = tuple(sorted(ports)[:MAX_PORTS_PER_PLAN])
    return NetworkValidationPlan(
        addresses=authorized_addresses, ports=bounded_ports, profile=profile,
    )
