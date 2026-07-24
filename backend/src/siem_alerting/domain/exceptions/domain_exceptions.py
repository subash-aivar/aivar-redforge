"""Domain exceptions for siem_alerting."""

from __future__ import annotations


class SiemAlertingDomainError(Exception):
    """Base domain error for siem_alerting."""


class TenantMismatch(SiemAlertingDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyDedupKeyError(SiemAlertingDomainError):
    def __init__(self) -> None:
        super().__init__("Alert.dedup_key must be a non-empty string")


class InvalidAlertTransition(SiemAlertingDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid alert transition {from_status} → {to_status}")
