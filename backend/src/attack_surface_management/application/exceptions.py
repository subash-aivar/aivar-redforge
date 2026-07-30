"""Application-layer errors for attack_surface_management (M49B),
mirroring `risk_engine.application.exceptions`'s shape exactly."""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-execution request-shape validation failure."""


class AssetNotFoundError(ApplicationValidationError):
    def __init__(self, asset_id: object) -> None:
        super().__init__(f"No asset found for id {asset_id!r}")
        self.asset_id = asset_id


class NetworkRangeNotFoundError(ApplicationValidationError):
    def __init__(self, range_id: object) -> None:
        super().__init__(f"No network range found for id {range_id!r}")
        self.range_id = range_id


class AssetTenantIsolationViolationError(ApplicationValidationError):
    """Raised by application-layer services when a command/query's
    `tenant_id` does not match the tenant that owns the referenced
    aggregate — distinct from the domain-layer `TenantMismatch` raised
    by the aggregates themselves. Also raised proactively before ever
    touching the repository when a command/query's own identifiers are
    malformed enough to represent a tenant-isolation risk."""

    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant isolation violation: expected {expected!r}, got {actual!r}")
        self.expected = expected
        self.actual = actual


class EmptyAssetIdentifierInputError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("At least one of domain_name, subdomain, or ip_address must be provided")


class InvalidPaginationError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid pagination: {reason}")
