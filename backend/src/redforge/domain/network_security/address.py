"""Canonical network-address normalization/classification/bounded-CIDR
expansion — M16.

Reuses `application.validation_execution.network_boundary.classify_address`
(and its underlying `AddressClass` enum) for classification vocabulary so
M16's inventory/UI/authorization decisions describe addresses with the
EXACT SAME taxonomy M11 already uses — never a second, competing address
classification scheme.

M16's ALLOW decision differs deliberately from M11's, and that
difference is a documented decision, not a regression of M11:
M11 (application/validation_execution/network_boundary.py) is a
categorical PUBLIC-only allowlist because it makes redirect-following,
attacker-influenced HTTP requests against a validated AI system's own
endpoint — there is no per-authorization scope concept for arbitrary
internal ranges there (see that module's own docstring). M16 is the
opposite shape: it only ever probes an address that a same-tenant
SecurityAuthorization has explicitly, freshly scoped (see
application/network_security/authorization_scope.py) — enterprise
network security monitoring is meaningless if it cannot ever reach an
organization's own private/loopback infrastructure. So M16 does not
reuse `is_address_allowed()` (M11's categorical gate) — the ALLOW
decision for M16 is authorization-driven per address, computed
elsewhere. This module only classifies and normalizes; it never itself
decides ALLOW/DENY.

Two address classes remain hard-denied here regardless of any
authorization, because no legitimate "network security monitoring"
scope could ever cover them:
  - MULTICAST: not a validatable single host.
  - UNSPECIFIED (0.0.0.0 / ::): not a routable destination.
Metadata addresses (AWS/GCP/Azure/OpenStack instance metadata) are also
hard-denied — see `_HARD_DENIED_CLASSES` — mirroring M11's treatment;
no legitimate network-security-monitoring scope should ever target
cloud metadata endpoints.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Self

from redforge.application.validation_execution.network_boundary import classify_address
from redforge.domain.validation_execution.value_objects import AddressClass

# Server-controlled hard cap on how many concrete addresses one
# NetworkValidationRun may plan against. Enforced BEFORE any
# materialization of the address list (see expand_cidr_bounded) — never
# `list(network.hosts())` first and truncated after.
MAX_NETWORK_ADDRESSES_PER_EXECUTION = 256

_HARD_DENIED_CLASSES: frozenset[AddressClass] = frozenset({
    AddressClass.MULTICAST,
    AddressClass.UNSPECIFIED,
    AddressClass.METADATA,
})


class NetworkAddressError(ValueError):
    """Raised for a malformed IP/CIDR — always a controlled 4xx at the
    API boundary, never an unhandled 500."""


class NetworkScopeTooLargeError(NetworkAddressError):
    """Raised when a CIDR's address count exceeds
    MAX_NETWORK_ADDRESSES_PER_EXECUTION. Reported to the caller as the
    stable reason code NETWORK_SCOPE_TOO_LARGE — never silently
    truncated."""

    def __init__(self, cidr: str, num_addresses: int, max_addresses: int) -> None:
        self.cidr = cidr
        self.num_addresses = num_addresses
        self.max_addresses = max_addresses
        super().__init__(
            f"'{cidr}' has {num_addresses} addresses, exceeding the maximum of "
            f"{max_addresses} per execution (NETWORK_SCOPE_TOO_LARGE)"
        )


@dataclass(frozen=True, slots=True)
class NormalizedAddress:
    """One canonicalized, classified IP address."""

    value: str
    version: int  # 4 or 6
    address_class: AddressClass

    @classmethod
    def parse(cls, raw: str) -> Self:
        value = raw.strip()
        try:
            addr = ipaddress.ip_address(value)
        except ValueError as exc:
            raise NetworkAddressError(f"'{raw}' is not a valid IP address") from exc
        return cls(value=str(addr), version=addr.version, address_class=classify_address(str(addr)))

    @property
    def is_hard_denied(self) -> bool:
        """True for address classes no authorization scope may ever
        cover (see module docstring) — checked unconditionally,
        independent of any SecurityAuthorization."""
        return self.address_class in _HARD_DENIED_CLASSES


@dataclass(frozen=True, slots=True)
class NormalizedNetwork:
    """One canonicalized CIDR network (host bits masked)."""

    value: str
    version: int
    prefix_length: int
    num_addresses: int

    @classmethod
    def parse(cls, raw: str) -> Self:
        value = raw.strip()
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise NetworkAddressError(f"'{raw}' is not a valid network/CIDR") from exc
        return cls(
            value=str(network), version=network.version,
            prefix_length=network.prefixlen, num_addresses=network.num_addresses,
        )

    def contains(self, address: str) -> bool:
        """True if `address` falls within this network. Never raises for
        a malformed address — treated as not contained (fail-closed for
        authorization-containment checks)."""
        try:
            ip = ipaddress.ip_address(address.strip())
            network = ipaddress.ip_network(self.value, strict=False)
        except ValueError:
            return False
        if ip.version != network.version:
            return False
        return ip in network


def normalize_and_classify(raw: str) -> NormalizedAddress:
    """Parse+classify one address. Raises NetworkAddressError (never a
    bare ValueError, never an unhandled exception) for malformed input."""
    return NormalizedAddress.parse(raw)


def normalize_network(raw: str) -> NormalizedNetwork:
    """Parse+normalize one CIDR. Raises NetworkAddressError for
    malformed input."""
    return NormalizedNetwork.parse(raw)


def expand_cidr_bounded(
    raw_cidr: str, max_addresses: int = MAX_NETWORK_ADDRESSES_PER_EXECUTION,
) -> list[str]:
    """Expand a CIDR to its concrete host addresses, but ONLY after
    verifying `num_addresses` is within `max_addresses` — the bounds
    check reads `ipaddress.ip_network.num_addresses` (an O(1) integer
    property), never materializes `.hosts()` first. `/0` is rejected
    unconditionally (matches M6's BoundedNetworkScanAdapter precedent)
    regardless of `max_addresses`, since it can never be a legitimately
    scoped-and-authorized target.

    Raises:
        NetworkAddressError: malformed CIDR, or prefix_length == 0.
        NetworkScopeTooLargeError: num_addresses > max_addresses.
    """
    network = NormalizedNetwork.parse(raw_cidr)
    if network.prefix_length == 0:
        raise NetworkAddressError(
            f"'{raw_cidr}' is a default route (/0) — an explicit, bounded, "
            "authorized range is required."
        )
    if network.num_addresses > max_addresses:
        raise NetworkScopeTooLargeError(network.value, network.num_addresses, max_addresses)

    ip_network = ipaddress.ip_network(network.value, strict=False)
    if ip_network.num_addresses > 2:
        return [str(a) for a in ip_network.hosts()]
    # /31, /32 (or IPv6 /127, /128): ipaddress.hosts() yields nothing
    # useful for these degenerate cases — every address in the network
    # is itself a valid target (point-to-point / single-host).
    return [str(a) for a in ip_network]
