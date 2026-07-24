"""Domain exceptions for cloud_security (M45A).

Independent of `siem_*`'s exception hierarchies — `cloud_security` is
its own bounded context and must not import SIEM domain objects."""

from __future__ import annotations


class CloudSecurityDomainError(Exception):
    """Base domain error for cloud_security."""


class TenantMismatch(CloudSecurityDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyDisplayNameError(CloudSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("display_name must be a non-empty string")


class InvalidCloudAccountTransition(CloudSecurityDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid CloudAccount connection transition {from_status} → {to_status}")


class InvalidDiscoveryTransition(CloudSecurityDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid discovery transition {from_state} → {to_state}")


class CredentialAlreadyLinkedError(CloudSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("CloudAccount already has a linked credential reference")


class DuplicateAccountMembershipError(CloudSecurityDomainError):
    def __init__(self, account_id: object) -> None:
        super().__init__(f"CloudAccount {account_id!r} is already a member of this organization")


class InvalidCloudArnError(CloudSecurityDomainError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid CloudArn: {raw!r} (expected 'arn:' prefix)")


class InvalidAzureResourceIdError(CloudSecurityDomainError):
    def __init__(self, raw: str) -> None:
        super().__init__(
            f"Invalid AzureResourceId: {raw!r} (expected '/subscriptions/' prefix)"
        )


class InvalidGcpResourceNameError(CloudSecurityDomainError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid GcpResourceName: {raw!r} (expected 'projects/' prefix)")


class InvalidTagKeyError(CloudSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("CloudTag.key must be a non-empty string")


class DuplicateTagKeyError(CloudSecurityDomainError):
    def __init__(self, key: str) -> None:
        super().__init__(f"CloudTagSet already contains a tag with key {key!r}")


class InvalidDiscoveryWindowError(CloudSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("DiscoveryWindow.end must be strictly after DiscoveryWindow.start")


class InvalidCloudMetadataKeyError(CloudSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("CloudMetadata keys must be non-empty strings")


class EmptyIdentifierError(CloudSecurityDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidAssetLifecycleTransition(CloudSecurityDomainError):
    def __init__(self, from_state: str, to_state: str) -> None:
        super().__init__(f"Invalid CloudAsset lifecycle transition {from_state} → {to_state}")


class EmptyMoveError(CloudSecurityDomainError):
    def __init__(self) -> None:
        super().__init__("move() requires at least one of account_id or region_id")


class InvalidProviderTransition(CloudSecurityDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid provider registration transition {from_status} → {to_status}")


class DuplicateCapabilityError(CloudSecurityDomainError):
    def __init__(self, capability: object) -> None:
        super().__init__(f"ProviderCapabilitySet already contains capability {capability!r}")


class InvalidCredentialAssociationTransition(CloudSecurityDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid CredentialAssociation transition {from_status} → {to_status}")


class RedundantCredentialReferenceError(CloudSecurityDomainError):
    """Raised when a replace/rotate is asked to swap in the exact
    reference that is already active — never a genuine rotation."""

    def __init__(self) -> None:
        super().__init__(
            "The replacement CloudCredentialReference is identical to the currently active one"
        )


class InvalidDiscoveryJobTransition(CloudSecurityDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid CloudDiscoveryJob transition {from_status} → {to_status}")


class InvalidEvaluationTransition(CloudSecurityDomainError):
    def __init__(self, from_status: str, to_status: str) -> None:
        super().__init__(f"Invalid CloudSecurityEvaluation transition {from_status} → {to_status}")


class EmptyRuleIdentifierError(CloudSecurityDomainError):
    def __init__(self, field_name: str) -> None:
        super().__init__(f"BaselineFinding.{field_name} must be a non-empty string")
