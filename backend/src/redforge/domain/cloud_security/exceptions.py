"""Domain exceptions for M26 Cloud Security foundation."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, NotFoundError, ValidationError


class InvalidCloudArgumentError(ValidationError):
    def __init__(self, field: str, message: str) -> None:
        self.field = field
        super().__init__(message=f"{field}: {message}", details={field: message})


class CloudProviderNotFoundError(NotFoundError):
    def __init__(self, provider_id: str) -> None:
        super().__init__(resource="CloudProvider", identifier=provider_id)
        self.provider_id = provider_id


class CloudAccountNotFoundError(NotFoundError):
    def __init__(self, account_id: str) -> None:
        super().__init__(resource="CloudAccount", identifier=account_id)
        self.account_id = account_id


class CloudProviderAlreadyExistsError(ConflictError):
    def __init__(self, organization_id: str, provider_type: str) -> None:
        self.organization_id = organization_id
        self.provider_type = provider_type
        super().__init__(
            message=(
                f"CloudProvider already registered for org={organization_id} type={provider_type}"
            ),
        )


class CloudAccountAlreadyExistsError(ConflictError):
    def __init__(self, provider_id: str, external_id: str) -> None:
        self.provider_id = provider_id
        self.external_id = external_id
        super().__init__(
            message=(
                f"CloudAccount already exists provider={provider_id} external_id={external_id}"
            ),
        )


class CloudProviderDisabledError(ConflictError):
    def __init__(self, provider_id: str) -> None:
        self.provider_id = provider_id
        super().__init__(message=f"CloudProvider is disabled: {provider_id}")


class TenantMismatchError(ValidationError):
    def __init__(self, expected: str, actual: str) -> None:
        super().__init__(
            message=f"organization_id mismatch expected={expected} actual={actual}",
            details={"expected": expected, "actual": actual},
        )


class CloudAssetNotFoundError(NotFoundError):
    def __init__(self, asset_id: str) -> None:
        super().__init__(resource="CloudAsset", identifier=asset_id)
        self.asset_id = asset_id


class CloudAssetDeletedError(ConflictError):
    def __init__(self, asset_id: str) -> None:
        self.asset_id = asset_id
        super().__init__(message=f"CloudAsset is deleted: {asset_id}")


class CloudAssetAlreadyExistsError(ConflictError):
    def __init__(self, account_id: str, provider_id: str) -> None:
        self.account_id = account_id
        self.provider_id = provider_id
        super().__init__(
            message=f"CloudAsset already exists account={account_id} provider_id={provider_id}",
        )


class CloudIAMPrincipalNotFoundError(NotFoundError):
    def __init__(self, principal_id: str) -> None:
        super().__init__(resource="CloudIAMPrincipal", identifier=principal_id)
        self.principal_id = principal_id


class CloudIAMPrincipalDeletedError(ConflictError):
    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id
        super().__init__(message=f"CloudIAMPrincipal is deleted: {principal_id}")


class CloudIAMPrincipalDisabledError(ConflictError):
    def __init__(self, principal_id: str) -> None:
        self.principal_id = principal_id
        super().__init__(message=f"CloudIAMPrincipal is disabled: {principal_id}")


class CloudIAMPrincipalAlreadyExistsError(ConflictError):
    def __init__(self, account_id: str, provider_id: str) -> None:
        self.account_id = account_id
        self.provider_id = provider_id
        super().__init__(
            message=(
                f"CloudIAMPrincipal already exists account={account_id} provider_id={provider_id}"
            ),
        )
