"""Domain exceptions for siem_search."""

from __future__ import annotations


class SiemSearchDomainError(Exception):
    """Base domain error for siem_search."""


class InvalidTimeRangeError(SiemSearchDomainError):
    def __init__(self) -> None:
        super().__init__("TimeRange.end must be strictly after TimeRange.start")
