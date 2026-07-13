"""Network-boundary policy — classifies a resolved IP address and
decides whether M11 active validation may ever connect to it.

This is the SSRF/pivot defense: by default, active validation may only
reach genuinely public addresses. There is no per-authorization
"explicit internal range" allowance in M10's scope model today (scope
entities are canonical `ai_target`/`ai_asset` IDs, not raw IP ranges) —
so private/loopback/link-local/reserved/multicast/metadata addresses
are denied categorically here, not conditionally. This is a deliberate,
documented v1 scope limit (see value_objects.AddressClass's docstring),
not a fabricated partial feature.

Used identically for the INITIAL DNS resolution and for EVERY redirect
hop's resolution — a redirect can never pivot into a class this module
denies, regardless of what the original target classified as.
"""

from __future__ import annotations

import ipaddress

from redforge.domain.validation_execution.value_objects import (
    ALLOWED_ADDRESS_CLASSES,
    AddressClass,
)

# Well-known cloud metadata addresses. These are ALSO link-local/private
# under RFC classification, so they would be denied either way — this
# set exists purely to give a more precise, auditable reason
# (AddressClass.METADATA rather than a generic LINK_LOCAL/PRIVATE) when
# one of these specific, security-sensitive addresses is the reason for
# denial.
_KNOWN_METADATA_ADDRESSES: frozenset[str] = frozenset({
    "169.254.169.254",  # AWS / GCP / Azure / OpenStack instance metadata
    "fd00:ec2::254",  # AWS IMDSv2 IPv6
    "169.254.170.2",  # AWS ECS task metadata
})


def classify_address(raw_address: str) -> AddressClass:
    """Classify one resolved address string. Never raises for a
    malformed address — an unparseable string is treated as RESERVED
    (denied), fail-safe."""
    if raw_address in _KNOWN_METADATA_ADDRESSES:
        return AddressClass.METADATA

    try:
        ip = ipaddress.ip_address(raw_address)
    except ValueError:
        return AddressClass.RESERVED

    if ip.is_loopback:
        return AddressClass.LOOPBACK
    if ip.is_link_local:
        return AddressClass.LINK_LOCAL
    if ip.is_multicast:
        return AddressClass.MULTICAST
    if ip.is_unspecified:
        return AddressClass.UNSPECIFIED
    if ip.is_private:
        return AddressClass.PRIVATE
    if ip.is_reserved:
        return AddressClass.RESERVED
    if ip.is_global:
        return AddressClass.PUBLIC
    # Defensive catch-all for any address class the `ipaddress` module
    # adds in the future that isn't covered above — fail closed.
    return AddressClass.RESERVED


def is_address_allowed(raw_address: str) -> bool:
    return classify_address(raw_address) in ALLOWED_ADDRESS_CLASSES
