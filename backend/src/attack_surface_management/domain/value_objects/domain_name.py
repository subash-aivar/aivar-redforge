"""DomainName / Subdomain value objects (M49A).

`DomainName` models a registrable/apex domain (e.g. `example.com`).
`Subdomain` models a fully-qualified label under a `DomainName` (e.g.
`app.example.com`) and always carries its parent `DomainName` so a
subdomain can never exist detached from the domain it belongs to."""

from __future__ import annotations

import re
from dataclasses import dataclass

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidDomainNameError,
    InvalidSubdomainError,
)

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")


@dataclass(frozen=True, slots=True)
class DomainName:
    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip().lower().rstrip(".")
        if not normalized or len(normalized) > 253 or not _DOMAIN_RE.match(normalized):
            raise InvalidDomainNameError(self.value)
        object.__setattr__(self, "value", normalized)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class Subdomain:
    fqdn: str
    parent: DomainName

    def __post_init__(self) -> None:
        normalized = self.fqdn.strip().lower().rstrip(".")
        if not normalized or not _DOMAIN_RE.match(normalized):
            raise InvalidSubdomainError(f"'{self.fqdn}' is not a valid FQDN")
        if not normalized.endswith(f".{self.parent.value}") and normalized != self.parent.value:
            raise InvalidSubdomainError(
                f"'{normalized}' is not a subdomain of '{self.parent.value}'"
            )
        object.__setattr__(self, "fqdn", normalized)

    def __str__(self) -> str:
        return self.fqdn
