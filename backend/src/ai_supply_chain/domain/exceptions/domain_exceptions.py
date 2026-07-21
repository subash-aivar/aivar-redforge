"""Domain exceptions for ai_supply_chain."""

from __future__ import annotations


class SupplyChainDomainError(Exception):
    """Base domain error."""


class TenantMismatch(SupplyChainDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class ChainEntryImmutable(SupplyChainDomainError):
    def __init__(self) -> None:
        super().__init__("ProvenanceChainEntry records are append-only")


class MBOMComponentImmutable(SupplyChainDomainError):
    def __init__(self) -> None:
        super().__init__("MBOM components are append-only once recorded")


class InvalidIntegrityTransition(SupplyChainDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid integrity transition {from_state} -> {to_state}")


class UnknownOriginCannotVerify(SupplyChainDomainError):
    def __init__(self) -> None:
        super().__init__("ModelOrigin=Unknown cannot transition to Verified")


class MBOMIncomplete(SupplyChainDomainError):
    def __init__(self) -> None:
        super().__init__("MBOM requires at least one BaseModel component to complete")


class SizeThresholdTooLow(SupplyChainDomainError):
    def __init__(self, minimum_bytes: int) -> None:
        super().__init__(f"Size threshold must be >= {minimum_bytes} bytes")


class VerificationBudgetExhausted(SupplyChainDomainError):
    def __init__(self, tenant_id: str) -> None:
        super().__init__(f"Verification egress budget exhausted for tenant {tenant_id}")


class MaxRetriesExceeded(SupplyChainDomainError):
    def __init__(self, provenance_id: str) -> None:
        super().__init__(
            f"More than 3 consecutive VerificationFailed for {provenance_id}; manual reset required"
        )
