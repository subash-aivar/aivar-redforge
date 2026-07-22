from __future__ import annotations


class ThreatHuntDomainError(Exception):
    pass


class DomainInvariantViolation(ThreatHuntDomainError):
    pass


class TenantMismatch(ThreatHuntDomainError):
    pass


class AuthorizationDenied(ThreatHuntDomainError):
    pass


class InvalidCandidateTransition(ThreatHuntDomainError):
    pass


class TenantIsolationViolation(ThreatHuntDomainError):
    pass
