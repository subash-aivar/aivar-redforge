"""Application-layer errors for risk_engine (M48C)."""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-execution request-shape validation failure."""


class InvalidSubjectReferenceError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid subject_reference: {reason}")


class EnterpriseRiskProfileNotFoundError(ApplicationValidationError):
    def __init__(self, profile_id: object) -> None:
        super().__init__(f"No enterprise risk profile found for id {profile_id!r}")
        self.profile_id = profile_id


class RiskCorrelationSetNotFoundError(ApplicationValidationError):
    def __init__(self, correlation_set_id: object) -> None:
        super().__init__(f"No risk correlation set found for id {correlation_set_id!r}")
        self.correlation_set_id = correlation_set_id


class RiskTenantIsolationViolationError(ApplicationValidationError):
    """Raised by application-layer services when a command/query's
    `tenant_id` does not match the tenant that owns the referenced
    aggregate — distinct from the domain-layer `TenantMismatch` raised
    by the aggregates themselves. Also raised proactively before ever
    touching the repository when a command's own identifiers are
    malformed enough to represent a tenant-isolation risk."""

    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant isolation violation: expected {expected!r}, got {actual!r}")
        self.expected = expected
        self.actual = actual


class EmptySignalsError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("At least one signal is required to recompute an enterprise risk score")


class RiskProfileNotAcceptedError(ApplicationValidationError):
    """Raised when acceptance-expiry evaluation is requested for a
    profile that is not currently in `RiskProfileStatus.ACCEPTED` —
    there is no acceptance window to evaluate expiry against."""

    def __init__(self, profile_id: object, status: object) -> None:
        super().__init__(
            f"Enterprise risk profile {profile_id!r} is not ACCEPTED (status={status!r}); "
            "no acceptance window to evaluate expiry against"
        )
        self.profile_id = profile_id
        self.status = status
