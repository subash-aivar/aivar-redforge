from __future__ import annotations


class AutonomousIntelligenceDomainError(Exception):
    pass


class DomainInvariantViolation(AutonomousIntelligenceDomainError):
    pass


class TenantMismatch(AutonomousIntelligenceDomainError):
    pass


class TenantIsolationViolation(AutonomousIntelligenceDomainError):
    pass


class AutonBoundaryViolation(AutonomousIntelligenceDomainError):
    pass


class InvalidSuggestionTransition(AutonomousIntelligenceDomainError):
    pass


class ConfidenceThresholdNotMet(AutonomousIntelligenceDomainError):
    pass


class AccuracyThresholdNotMet(AutonomousIntelligenceDomainError):
    pass


class AuthorizationDenied(AutonomousIntelligenceDomainError):
    pass


class InvalidModelTransition(AutonomousIntelligenceDomainError):
    pass
