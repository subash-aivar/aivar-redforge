from __future__ import annotations


class PostureForecastingDomainError(Exception):
    pass


class DomainInvariantViolation(PostureForecastingDomainError):
    pass


class TenantMismatch(PostureForecastingDomainError):
    pass
