"""Domain exceptions for siem_normalization."""

from __future__ import annotations


class SiemNormalizationDomainError(Exception):
    """Base domain error for siem_normalization."""


class EmptyBatchFingerprintError(SiemNormalizationDomainError):
    def __init__(self) -> None:
        super().__init__("batch_fingerprint must be a non-empty string")


class NoNormalizedEventsError(SiemNormalizationDomainError):
    def __init__(self) -> None:
        super().__init__("EventsNormalized requires normalized_event_count > 0")


class EmptyFailureDetailError(SiemNormalizationDomainError):
    def __init__(self) -> None:
        super().__init__("NormalizationFailed.detail must be a non-empty, actionable string")
