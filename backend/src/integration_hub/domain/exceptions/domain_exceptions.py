from __future__ import annotations


class IntegrationHubDomainError(Exception):
    pass


class DomainInvariantViolation(IntegrationHubDomainError):
    pass


class TenantMismatch(IntegrationHubDomainError):
    pass


class CircuitOpenError(IntegrationHubDomainError):
    pass


class ConnectorDisabledError(IntegrationHubDomainError):
    pass


class ConcurrencyConflictError(IntegrationHubDomainError):
    """Raised when an optimistic-lock version check fails on update —
    another writer (e.g. a concurrent sync run) modified the row first."""
