"""Hosting/ownership value objects — provider references, geographic
region, and network ownership. All RedForge-native and defined locally:
no cross-import of `cloud_security`, `attack_surface_management` or
`redforge.domain.inventory`, which model RedForge's OWN cloud accounts,
discovered attack surface and AI asset inventory respectively — all
unrelated to ADVERSARY hosting footprints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from infrastructure_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from infrastructure_intel.domain.value_objects.enums import CloudProvider


@dataclass(frozen=True, slots=True)
class HostingProviderRef:
    """The hosting provider behind this footprint, by name.

    Deliberately a free string, not a closed enum: hosting providers
    (and bulletproof-hosting fronts especially) appear, rebrand and
    vanish continuously, and a closed vocabulary would go stale the
    week it shipped."""

    provider_name: str

    def __post_init__(self) -> None:
        if not self.provider_name.strip():
            raise EmptyIdentifierError("provider_name")

    def __str__(self) -> str:
        return self.provider_name


@dataclass(frozen=True, slots=True)
class CloudProviderRef:
    """The cloud tenancy this footprint sits in. Closed enum — the
    hyperscaler set genuinely is small and slow-moving, with `OTHER` as
    the honest escape hatch."""

    provider: CloudProvider

    def __str__(self) -> str:
        return self.provider.value


@dataclass(frozen=True, slots=True)
class Region:
    """A geographic/provider region this footprint operates in — e.g.
    "us-east-1", "EMEA", "eu-west".

    Format/non-empty-validated only, never a closed enum: geography
    does not close, and every cloud provider coins its own region
    codes on its own schedule."""

    region_code: str

    def __post_init__(self) -> None:
        if not self.region_code.strip():
            raise EmptyIdentifierError("region_code")

    def __str__(self) -> str:
        return self.region_code


@dataclass(frozen=True, slots=True)
class NetworkOwnership:
    """Registrant/abuse-contact ownership metadata, as asserted by a
    registry (RIR/WHOIS) or by an analyst. `registrant_organization` is
    required when ownership IS asserted; the rest is genuinely
    optional."""

    registrant_organization: str
    abuse_contact: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.registrant_organization.strip():
            raise EmptyIdentifierError("registrant_organization")

    def __str__(self) -> str:
        return self.registrant_organization
