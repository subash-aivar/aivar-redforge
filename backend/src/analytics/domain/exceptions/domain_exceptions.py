"""Domain exceptions for analytics."""

from __future__ import annotations


class AnalyticsDomainError(Exception):
    pass


class TenantContextMissingError(AnalyticsDomainError):
    pass


class TenantMismatch(AnalyticsDomainError):
    pass


class InvalidDataSetTransition(AnalyticsDomainError):
    pass


class AnalyticsQueryValidationError(AnalyticsDomainError):
    pass


class InsufficientTrainingDataError(AnalyticsDomainError):
    pass
