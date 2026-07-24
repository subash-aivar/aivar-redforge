"""Domain exceptions for siem_storage."""

from __future__ import annotations


class SiemStorageDomainError(Exception):
    """Base domain error for siem_storage."""


class InvalidRetentionDurationError(SiemStorageDomainError):
    def __init__(self, days: int) -> None:
        super().__init__(f"Retention duration must be a positive number of days, got {days}")


class UnknownCategoryError(SiemStorageDomainError):
    def __init__(self, category: str) -> None:
        super().__init__(f"No retention duration configured for category '{category}'")


class NoTransitionFromArchiveError(SiemStorageDomainError):
    def __init__(self) -> None:
        super().__init__("ARCHIVE is the terminal tier — there is no next tier to transition to")
