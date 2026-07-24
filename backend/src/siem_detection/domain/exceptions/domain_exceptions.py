"""Domain exceptions for siem_detection."""

from __future__ import annotations


class SiemDetectionDomainError(Exception):
    """Base domain error for siem_detection."""


class TenantMismatch(SiemDetectionDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyRuleBodyError(SiemDetectionDomainError):
    def __init__(self) -> None:
        super().__init__("DetectionRule.rule_body must be a non-empty string")


class EmptyRuleNameError(SiemDetectionDomainError):
    def __init__(self) -> None:
        super().__init__("DetectionRule.name must be a non-empty string")


class InvalidRuleTransition(SiemDetectionDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid detection rule transition {from_status} → {to_status}")
