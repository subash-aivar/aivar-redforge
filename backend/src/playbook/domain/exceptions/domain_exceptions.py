"""Playbook domain exceptions."""

from __future__ import annotations


class PlaybookDomainError(Exception):
    pass


class DomainInvariantViolation(PlaybookDomainError):
    pass


class TenantMismatch(PlaybookDomainError):
    pass


class PlaybookAuthorizationDenied(PlaybookDomainError):
    pass


class SeparationOfDutiesViolation(PlaybookDomainError):
    pass


class DryRunRequired(PlaybookDomainError):
    pass


class DryRunHashMismatch(PlaybookDomainError):
    pass


class DryRunNotPassed(PlaybookDomainError):
    pass


class KillSwitchActive(PlaybookDomainError):
    pass


class InvalidPlaybookTransition(PlaybookDomainError):
    pass


class VersionImmutableError(PlaybookDomainError):
    pass
