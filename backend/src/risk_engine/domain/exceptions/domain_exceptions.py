"""Domain exceptions for risk_engine (M48B).

Independent of `vulnerability_engine`, `ai_security`, `cloud_security`,
and every other bounded context's exception hierarchy — risk_engine is
its own bounded context and must not import domain objects from any of
them."""

from __future__ import annotations


class RiskEngineDomainError(Exception):
    """Base domain error for risk_engine."""


class TenantMismatch(RiskEngineDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(RiskEngineDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidRiskProfileTransition(RiskEngineDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid RiskProfile status transition {from_status} → {to_status}")


class InvalidNormalizedRiskScoreError(RiskEngineDomainError):
    def __init__(self, value: float) -> None:
        super().__init__(f"NormalizedRiskScore must be between 0.0 and 10.0, got {value}")


class InvalidRiskSignalReferenceError(RiskEngineDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid RiskSignalReference: {reason}")


class InvalidRiskWeightProfileError(RiskEngineDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid RiskWeightProfile: {reason}")


class InvalidCorrelationSetError(RiskEngineDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid RiskCorrelationSet: {reason}")


class EmptyContributionsError(RiskEngineDomainError):
    def __init__(self) -> None:
        super().__init__("At least one RiskContribution is required")


class UnsupportedRiskScaleError(RiskEngineDomainError):
    def __init__(self, scale: object) -> None:
        super().__init__(
            f"RiskScale {scale!r} requires the raw_value to already be pre-normalized "
            "to the 0-10 scale by the caller"
        )
