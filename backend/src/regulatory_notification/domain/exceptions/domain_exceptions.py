from __future__ import annotations


class RegulatoryDomainError(Exception):
    pass


class TenantMismatch(RegulatoryDomainError):
    pass


class DomainInvariantViolation(RegulatoryDomainError):
    pass


class InvalidNotificationTransition(RegulatoryDomainError):
    pass


class AutoSubmissionProhibited(RegulatoryDomainError):
    pass
