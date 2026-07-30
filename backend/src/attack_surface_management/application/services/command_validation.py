"""Minimal shared command-shape validation for attack_surface_management
(M49B), mirroring `risk_engine.application.services.command_validation`'s
pattern exactly. Only request-shape checks that the domain layer itself
does not already perform live here — everything else (e.g. valid CIDR,
valid domain name, port-number bounds, non-empty owning team) is
delegated to domain value-object/aggregate validation, never
duplicated."""

from __future__ import annotations

from typing import TYPE_CHECKING

from attack_surface_management.application.exceptions import (
    EmptyAssetIdentifierInputError,
    InvalidPaginationError,
)

if TYPE_CHECKING:
    from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
    from attack_surface_management.domain.value_objects.ip_address import IPAddress

_MAX_LIMIT = 1000


def validate_asset_identifier_present(
    domain_name: DomainName | None,
    subdomain: Subdomain | None,
    ip_address: IPAddress | None,
) -> None:
    """`Asset`'s own `__init__` enforces this too, but validating it
    here lets `RegisterAssetCommand` fail fast, before any factory/
    repository work, with an application-layer error rather than
    surfacing the domain exception directly to callers."""
    if domain_name is None and subdomain is None and ip_address is None:
        raise EmptyAssetIdentifierInputError()


def validate_pagination(limit: int, offset: int) -> None:
    if limit <= 0 or limit > _MAX_LIMIT:
        raise InvalidPaginationError(f"limit must be between 1 and {_MAX_LIMIT}, got {limit}")
    if offset < 0:
        raise InvalidPaginationError(f"offset must be >= 0, got {offset}")
