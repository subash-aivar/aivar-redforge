"""Application-layer errors for cloud_security (M45A, extended M45B for
the Asset Inventory, M45C for the Provider Framework, and M45D for
Credential Integration)."""

from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationValidationError(ApplicationError):
    """Base type for every pre-execution request-shape validation failure."""


class InvalidDisplayNameError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid display_name: {reason}")


class InvalidTagError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid tag: {reason}")


class ProviderSelectionError(ApplicationError):
    """Base type for every cloud-provider-selection failure."""


class UnsupportedProviderError(ProviderSelectionError):
    def __init__(self, platform_type: object) -> None:
        super().__init__(f"No cloud provider registered for platform type {platform_type!r}")
        self.platform_type = platform_type


class DuplicateProviderRegistrationError(ApplicationError):
    def __init__(self, platform_type: object) -> None:
        super().__init__(
            f"A cloud provider for platform type {platform_type!r} is already registered"
        )
        self.platform_type = platform_type


# ---------------------------------------------------------------------------
# M45B — Asset Inventory
# ---------------------------------------------------------------------------


class DuplicateAssetIdError(ApplicationValidationError):
    def __init__(self, asset_id: object) -> None:
        super().__init__(f"An asset with id {asset_id!r} is already registered in the inventory")
        self.asset_id = asset_id


class InvalidRegionError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid region: {reason}")


class InvalidProviderError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid provider: {reason}")


class InvalidOwnershipError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid ownership: {reason}")


class EmptyBatchAssetError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("BatchAssetCommand.commands must contain at least one command")


# ---------------------------------------------------------------------------
# M45C — Provider Framework
# ---------------------------------------------------------------------------


class DuplicateProviderForPlatformError(ApplicationValidationError):
    """Distinct from `DuplicateProviderRegistrationError` (M45A's
    `ICloudProviderRegistry`, global per-platform plug-in registration,
    no tenant): this is the Provider Framework's own tenant-scoped
    "one registration per platform per tenant" rule."""

    def __init__(self, tenant_id: object, platform_type: object) -> None:
        super().__init__(
            f"Tenant {tenant_id!r} already has a provider registered for platform type "
            f"{platform_type!r}"
        )
        self.tenant_id = tenant_id
        self.platform_type = platform_type


class ProviderNotFoundError(ApplicationValidationError):
    def __init__(self, provider_id: object) -> None:
        super().__init__(f"No provider registration found for id {provider_id!r}")
        self.provider_id = provider_id


class InvalidCapabilityError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid capability: {reason}")


class EmptyBatchProviderError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("BatchProviderCommand.commands must contain at least one command")


# ---------------------------------------------------------------------------
# M45D — Credential Integration
# ---------------------------------------------------------------------------


class CredentialAssociationNotFoundError(ApplicationValidationError):
    def __init__(self, association_id: object) -> None:
        super().__init__(f"No credential association found for id {association_id!r}")
        self.association_id = association_id


class DuplicateCredentialAttachmentError(ApplicationValidationError):
    """One active `CredentialAssociation` per (tenant, account,
    provider) — a second `attach` for the same pair must go through
    `replace`, never a silent second attachment."""

    def __init__(self, account_id: object, provider_id: object) -> None:
        super().__init__(
            f"Account {account_id!r} already has an active credential association for "
            f"provider {provider_id!r}"
        )
        self.account_id = account_id
        self.provider_id = provider_id


class AccountMismatchError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Account mismatch: {reason}")


class ProviderMismatchError(ApplicationValidationError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Provider mismatch: {reason}")


class MissingCredentialReferenceError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("No active CloudCredentialReference to act on")


class EmptyBatchCredentialError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("BatchCredentialCommand.commands must contain at least one command")


# ---------------------------------------------------------------------------
# M45E — Resource Discovery
# ---------------------------------------------------------------------------


class ProviderNotEnabledError(ApplicationValidationError):
    """Shared across M45E (Resource Discovery) and M45F (Security
    Baseline) — both require an `ENABLED` `CloudProviderRegistration`
    before proceeding."""

    def __init__(self, provider_id: object) -> None:
        super().__init__(f"Provider {provider_id!r} is not ENABLED")
        self.provider_id = provider_id


class MissingDiscoveryCapabilityError(ApplicationValidationError):
    def __init__(self, provider_id: object) -> None:
        super().__init__(f"Provider {provider_id!r} does not claim the DISCOVERY capability")
        self.provider_id = provider_id


class CredentialNotAttachedError(ApplicationValidationError):
    def __init__(self, account_id: object, provider_id: object) -> None:
        super().__init__(
            f"No active credential association for account {account_id!r} and provider "
            f"{provider_id!r} — attach a credential before starting discovery"
        )
        self.account_id = account_id
        self.provider_id = provider_id


class DuplicateDiscoveryJobError(ApplicationValidationError):
    """One active (`IN_PROGRESS`) `CloudDiscoveryJob` per (tenant,
    account, provider) at a time."""

    def __init__(self, account_id: object, provider_id: object) -> None:
        super().__init__(
            f"Account {account_id!r} already has an in-progress discovery job for provider "
            f"{provider_id!r}"
        )
        self.account_id = account_id
        self.provider_id = provider_id


class DiscoveryJobNotFoundError(ApplicationValidationError):
    def __init__(self, job_id: object) -> None:
        super().__init__(f"No discovery job found for id {job_id!r}")
        self.job_id = job_id


class NoDiscoveryProviderRegisteredError(ApplicationValidationError):
    def __init__(self, platform_type: object) -> None:
        super().__init__(f"No IDiscoveryProvider registered for platform type {platform_type!r}")
        self.platform_type = platform_type


class EmptyBatchDiscoveryError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("BatchDiscoveryCommand.commands must contain at least one command")


# ---------------------------------------------------------------------------
# M45F — Security Baseline (CSPM Foundation)
# ---------------------------------------------------------------------------


class MissingBaselineCapabilityError(ApplicationValidationError):
    def __init__(self, provider_id: object) -> None:
        super().__init__(
            f"Provider {provider_id!r} does not claim the SECURITY_BASELINE capability"
        )
        self.provider_id = provider_id


class AssetNotActiveError(ApplicationValidationError):
    def __init__(self, asset_id: object) -> None:
        super().__init__(f"CloudAsset {asset_id!r} is not ACTIVE — it cannot be evaluated")
        self.asset_id = asset_id


class DuplicateEvaluationError(ApplicationValidationError):
    """One active (`IN_PROGRESS`) `CloudSecurityEvaluation` per
    (tenant, account, provider) at a time."""

    def __init__(self, account_id: object, provider_id: object) -> None:
        super().__init__(
            f"Account {account_id!r} already has an in-progress evaluation for provider "
            f"{provider_id!r}"
        )
        self.account_id = account_id
        self.provider_id = provider_id


class EvaluationNotFoundError(ApplicationValidationError):
    def __init__(self, evaluation_id: object) -> None:
        super().__init__(f"No security evaluation found for id {evaluation_id!r}")
        self.evaluation_id = evaluation_id


class NoBaselineProviderRegisteredError(ApplicationValidationError):
    def __init__(self, platform_type: object) -> None:
        super().__init__(f"No IBaselineProvider registered for platform type {platform_type!r}")
        self.platform_type = platform_type


class EmptyBatchBaselineError(ApplicationValidationError):
    def __init__(self) -> None:
        super().__init__("BatchBaselineCommand.commands must contain at least one command")
