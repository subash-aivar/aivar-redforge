"""Domain exceptions for ai_posture."""

from __future__ import annotations


class AIPostureDomainError(Exception):
    """Base domain error."""


class TenantMismatch(AIPostureDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class InvalidLifecycleTransition(AIPostureDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid lifecycle transition {from_state} → {to_state}")


class AggregateSealed(AIPostureDomainError):
    def __init__(self, aggregate_id: str) -> None:
        super().__init__(f"Aggregate sealed (decommissioned): {aggregate_id}")


class OwnerRequiredForRegistration(AIPostureDomainError):
    def __init__(self) -> None:
        super().__init__("BusinessOwnerRef is required before Registered state")


class ShadowAIBlocksRegistration(AIPostureDomainError):
    def __init__(self) -> None:
        super().__init__("Cannot move to Registered while RegistrationStatus is ShadowAI")


class InvalidAlertTransition(AIPostureDomainError):
    def __init__(self, from_state: str, action: str) -> None:
        super().__init__(f"Invalid alert transition from {from_state} for action {action}")


class ResolutionActionRequired(AIPostureDomainError):
    def __init__(self) -> None:
        super().__init__("ResolutionAction is required to resolve a ShadowAIAlert")


class FalsePositiveReasonRequired(AIPostureDomainError):
    def __init__(self) -> None:
        super().__init__("ConfirmedFalsePositive requires a documented reason")


class CategoryNotApplicable(AIPostureDomainError):
    def __init__(self, category: str) -> None:
        super().__init__(f"Threat category not applicable: {category}")


class CriticalExposureRequiresEvidence(AIPostureDomainError):
    def __init__(self) -> None:
        super().__init__("Critical exposure requires at least one AssessmentEvidenceRef")


class ThreatProfileArchived(AIPostureDomainError):
    def __init__(self, profile_id: str) -> None:
        super().__init__(f"Threat profile archived: {profile_id}")


class SnapshotImmutable(AIPostureDomainError):
    def __init__(self) -> None:
        super().__init__("AIRiskScoreSnapshot is immutable once created")


class InventoryAssetNotFound(AIPostureDomainError):
    def __init__(self, asset_id: str) -> None:
        super().__init__(f"M22 AssetRef not resolvable: {asset_id}")


class AttestationRequiredCannotAutoSatisfy(AIPostureDomainError):
    def __init__(self, control_id: str) -> None:
        super().__init__(f"Attestation-required control cannot be auto-satisfied: {control_id}")
