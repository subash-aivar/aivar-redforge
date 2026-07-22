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
