"""Domain exceptions for the Investigation bounded context — M21."""

from __future__ import annotations


class InvestigationNotFoundError(ValueError):
    """Raised when a requested investigation does not exist for the org."""


class InvalidStatusTransitionError(ValueError):
    """Raised when an illegal status transition is attempted."""


class CrossTenantCorrelationError(RuntimeError):
    """Raised when correlation would link evidence from different orgs.

    This must never happen. Raising an error is safer than silently
    dropping cross-tenant evidence.
    """


class StaleInvestigationError(RuntimeError):
    """Raised when an optimistic concurrency check fails.

    Caller should reload and retry the transition.
    """


class DuplicateEvidenceError(ValueError):
    """Raised when the same evidence dedup_key is already attached."""


class InvestigationAlreadyResolvedError(ValueError):
    """Raised when a mutation is attempted on a RESOLVED investigation
    that requires an active case (e.g., transition to ACKNOWLEDGED)."""
