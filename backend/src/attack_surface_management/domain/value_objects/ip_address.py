"""IPAddress value object (M49A) — wraps `ipaddress.ip_address` for
validated, immutable IPv4/IPv6 handling."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from attack_surface_management.domain.exceptions.domain_exceptions import InvalidIpAddressError


@dataclass(frozen=True, slots=True)
class IPAddress:
    value: str
    _parsed: ipaddress.IPv4Address | ipaddress.IPv6Address = field(
        init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        try:
            parsed = ipaddress.ip_address(self.value.strip())
        except ValueError as exc:
            raise InvalidIpAddressError(self.value) from exc
        object.__setattr__(self, "value", str(parsed))
        object.__setattr__(self, "_parsed", parsed)

    @property
    def is_private(self) -> bool:
        return self._parsed.is_private

    @property
    def version(self) -> int:
        return self._parsed.version

    def __str__(self) -> str:
        return self.value
