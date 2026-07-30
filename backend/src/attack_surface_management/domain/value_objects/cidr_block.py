"""CidrBlock value object (M49A) — wraps `ipaddress.ip_network` for a
validated, immutable CIDR range. Owned by the `NetworkRange` aggregate,
not by `Asset` — a range groups many assets, the inverse cardinality of
containment, so it is modeled as its own aggregate root rather than a
child of `Asset` (see `NetworkRange` for the boundary rationale)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from attack_surface_management.domain.exceptions.domain_exceptions import InvalidCidrBlockError


@dataclass(frozen=True, slots=True)
class CidrBlock:
    value: str
    _parsed: ipaddress.IPv4Network | ipaddress.IPv6Network = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        try:
            parsed = ipaddress.ip_network(self.value.strip(), strict=False)
        except ValueError as exc:
            raise InvalidCidrBlockError(self.value) from exc
        object.__setattr__(self, "value", str(parsed))
        object.__setattr__(self, "_parsed", parsed)

    @property
    def num_addresses(self) -> int:
        return self._parsed.num_addresses

    @property
    def version(self) -> int:
        return self._parsed.version

    def contains(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip.strip()) in self._parsed
        except ValueError:
            return False

    def __str__(self) -> str:
        return self.value
