"""Domain ↔ ORM mapping for CloudProvider and CloudAccount."""

from __future__ import annotations

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.entities import CloudRegion
from redforge.domain.cloud_security.value_objects import (
    AccountSyncState,
    CloudAccountId,
    CloudAccountMetadata,
    CloudAccountType,
    CloudProviderId,
    CloudProviderStatus,
    CloudProviderType,
    CredentialRef,
    DiscoveryConfig,
    OrganizationId,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudAccountModel,
    CloudProviderModel,
)


def provider_to_model(
    provider: CloudProvider, model: CloudProviderModel | None = None
) -> CloudProviderModel:
    target = model or CloudProviderModel(id=provider.id.value)
    target.id = provider.id.value
    target.organization_id = str(provider.organization_id)
    target.provider_type = provider.provider_type.value
    target.display_name = provider.display_name
    target.discovery_config = provider.discovery_config.to_dict()
    target.status = provider.status.value
    target.created_at = provider.created_at
    target.updated_at = provider.updated_at
    target.row_version = provider.version
    return target


def provider_from_model(model: CloudProviderModel) -> CloudProvider:
    return CloudProvider(
        id=CloudProviderId(model.id),
        organization_id=OrganizationId(model.organization_id),
        provider_type=CloudProviderType(model.provider_type),
        display_name=model.display_name,
        discovery_config=DiscoveryConfig.from_dict(dict(model.discovery_config)),
        status=CloudProviderStatus(model.status),
        created_at=model.created_at,
        updated_at=model.updated_at,
        version=model.row_version,
    )


def account_to_model(
    account: CloudAccount, model: CloudAccountModel | None = None
) -> CloudAccountModel:
    target = model or CloudAccountModel(id=account.id.value)
    target.id = account.id.value
    target.cloud_provider_id = account.cloud_provider_id.value
    target.organization_id = str(account.organization_id)
    target.external_id = account.external_id
    target.display_name = account.display_name
    target.account_type = account.account_type.value
    target.regions = [region.to_dict() for region in account.regions]
    target.credential_ref = {"reference_id": account.credential_ref.reference_id}
    target.sync_state = account.sync_state.to_dict()
    target.account_metadata = account.metadata.to_dict()
    target.tags = dict(account.tags)
    target.created_at = account.created_at
    target.updated_at = account.updated_at
    target.row_version = account.version
    return target


def account_from_model(model: CloudAccountModel) -> CloudAccount:
    regions_raw = model.regions or []
    regions = tuple(CloudRegion.from_dict(item) for item in regions_raw if isinstance(item, dict))
    cred = model.credential_ref or {}
    return CloudAccount(
        id=CloudAccountId(model.id),
        cloud_provider_id=CloudProviderId(model.cloud_provider_id),
        organization_id=OrganizationId(model.organization_id),
        external_id=model.external_id,
        display_name=model.display_name,
        account_type=CloudAccountType(model.account_type),
        regions=regions,
        credential_ref=CredentialRef(reference_id=str(cred["reference_id"])),
        sync_state=AccountSyncState.from_dict(dict(model.sync_state)),
        metadata=CloudAccountMetadata.from_dict(
            {str(k): str(v) for k, v in dict(model.account_metadata or {}).items()}
        ),
        tags={str(k): str(v) for k, v in dict(model.tags or {}).items()},
        created_at=model.created_at,
        updated_at=model.updated_at,
        version=model.row_version,
    )
