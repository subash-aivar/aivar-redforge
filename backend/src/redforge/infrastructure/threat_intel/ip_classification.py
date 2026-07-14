"""Public/private IP classification — the gate every outbound enrichment
call must pass through first.

RFC1918, loopback, link-local, multicast, reserved, documentation, and
other non-public ranges are never submitted to a public reputation or
geolocation provider. This module has zero knowledge of any provider —
it is a pure, dependency-free classification boundary so every call site
(reputation, geolocation, RDAP) shares exactly one definition of "public".
"""

from __future__ import annotations

import ipaddress


def is_public_ip(value: str) -> bool:
    """True only for a genuinely public, routable IPv4/IPv6 address.

    False for: private (RFC1918), loopback, link-local, multicast,
    reserved, unspecified, documentation/test-net ranges (RFC 5737/3849),
    and anything that fails to parse as an IP address at all (e.g. a
    hostname — this function is IP-only; callers must resolve/validate
    separately if they accept free-text input).
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    site_local = isinstance(addr, ipaddress.IPv6Address) and addr.is_site_local
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or site_local  # legacy IPv6 site-local (deprecated but non-public)
    )


def classify_indicator_for_egress(value: str, indicator_type: str) -> bool:
    """Whether this indicator is safe to submit to a public provider.

    Only IP-type indicators are subject to the public/private check —
    domains/URLs/hashes carry no address-space concept and are allowed
    through this gate (a domain can still be rejected downstream for
    other reasons, e.g. an internal-only hostname allowlist, but that is
    a separate concern from RFC1918/loopback/etc. filtering).
    """
    if indicator_type != "ip":
        return True
    return is_public_ip(value)
