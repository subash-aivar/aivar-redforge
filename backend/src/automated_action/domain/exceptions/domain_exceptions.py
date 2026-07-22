from __future__ import annotations


class AutomationDomainError(Exception):
    pass


class DomainInvariantViolation(AutomationDomainError):
    pass


class TenantMismatch(AutomationDomainError):
    pass


class SeparationOfDutiesViolation(AutomationDomainError):
    pass


class KillSwitchActive(AutomationDomainError):
    pass


class PolicyDenied(AutomationDomainError):
    pass


class EscalationTimeout(AutomationDomainError):
    pass


class InvalidExecutionTransition(AutomationDomainError):
    pass
