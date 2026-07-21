"""Domain exceptions for remediation_impact."""

from __future__ import annotations


class RemediationImpactDomainError(Exception):
    pass


class InvalidPlanTransition(RemediationImpactDomainError):
    pass


class TenantMismatch(RemediationImpactDomainError):
    pass


class EmptyCandidateSet(RemediationImpactDomainError):
    pass
