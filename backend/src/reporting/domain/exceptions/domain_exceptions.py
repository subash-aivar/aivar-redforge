"""Domain exceptions for reporting."""

from __future__ import annotations


class ReportingDomainError(Exception):
    pass


class TenantContextMissingError(ReportingDomainError):
    pass


class TenantMismatch(ReportingDomainError):
    pass


class InvalidReportTransition(ReportingDomainError):
    pass


class InvalidScheduleTransition(ReportingDomainError):
    pass


class UnsupportedReportType(ReportingDomainError):
    pass


class TemplateNotFound(ReportingDomainError):
    pass
