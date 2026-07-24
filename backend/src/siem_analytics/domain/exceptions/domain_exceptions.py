"""Domain exceptions for siem_analytics."""

from __future__ import annotations


class SiemAnalyticsDomainError(Exception):
    """Base domain error for siem_analytics."""


class NegativeMetricValueError(SiemAnalyticsDomainError):
    def __init__(self, value: float) -> None:
        super().__init__(f"MetricSample.value must be >= 0, got {value}")


class InvalidTimeRangeError(SiemAnalyticsDomainError):
    def __init__(self) -> None:
        super().__init__("TimeRange.end must be strictly after TimeRange.start")


class InvalidGroupByFieldError(SiemAnalyticsDomainError):
    def __init__(self) -> None:
        super().__init__("GroupByField.field_name must be a non-empty string")
