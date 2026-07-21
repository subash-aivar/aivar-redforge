"""Domain exceptions for exposure_reporting."""

from __future__ import annotations


class ExposureReportingDomainError(Exception):
    pass


class TenantMismatch(ExposureReportingDomainError):
    pass


class DuplicateBusinessImpactMapping(ExposureReportingDomainError):
    pass


class InvalidReportTransition(ExposureReportingDomainError):
    pass


class MappingNotFound(ExposureReportingDomainError):
    pass
