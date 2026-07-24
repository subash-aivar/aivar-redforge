"""Domain exceptions for siem_ingestion."""

from __future__ import annotations


class SiemIngestionDomainError(Exception):
    """Base domain error for siem_ingestion."""


class TenantMismatch(SiemIngestionDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyBatchError(SiemIngestionDomainError):
    def __init__(self) -> None:
        super().__init__("IngestedEventBatch requires event_count > 0")


class InvalidBatchFingerprintError(SiemIngestionDomainError):
    def __init__(self) -> None:
        super().__init__("IngestedEventBatch.batch_fingerprint must be a non-empty string")


class InvalidBatchTransition(SiemIngestionDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid batch transition {from_status} → {to_status}")
