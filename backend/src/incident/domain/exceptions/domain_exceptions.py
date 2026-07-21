from __future__ import annotations


class IncidentDomainError(Exception):
    """Base domain error."""


class TenantMismatch(IncidentDomainError):
    pass


class InvalidPhaseTransition(IncidentDomainError):
    pass


class AuthorizationDenied(IncidentDomainError):
    pass


class DomainInvariantViolation(IncidentDomainError):
    pass


class ClosureRequirementsNotMet(IncidentDomainError):
    pass


class CommunicationLogTampered(IncidentDomainError):
    pass
