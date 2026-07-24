"""Domain exceptions for siem_correlation."""

from __future__ import annotations


class SiemCorrelationDomainError(Exception):
    """Base domain error for siem_correlation."""


class TenantMismatch(SiemCorrelationDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class SessionAlreadyExpiredError(SiemCorrelationDomainError):
    """Raised on any attempt to accumulate into or match an expired
    session — the explicit guard against the "God aggregate accumulating
    forever" failure mode M37 §6/§22 names as the architecture's highest
    execution risk."""

    def __init__(self, session_id: object) -> None:
        super().__init__(f"CorrelationSession {session_id} has already expired")


class SessionAlreadyMatchedError(SiemCorrelationDomainError):
    def __init__(self, session_id: object) -> None:
        super().__init__(f"CorrelationSession {session_id} has already matched")


class WindowExpiryNotInFutureError(SiemCorrelationDomainError):
    def __init__(self) -> None:
        super().__init__("window_expires_at must be strictly after the session's open time")


class EmptyRuleIdError(SiemCorrelationDomainError):
    def __init__(self) -> None:
        super().__init__("CorrelationSession.rule_id must be a non-empty string")
