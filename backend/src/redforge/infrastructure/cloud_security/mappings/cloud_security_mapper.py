"""Domain ↔ ORM mapping for CloudProvider, CloudAccount, CloudAsset, CloudIAMPrincipal."""

from __future__ import annotations

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.entities import (
    AssetRelationship,
    AvailabilityZone,
    CloudRegion,
    IAMRiskIndicator,
    PolicyAttachment,
    TrustRelationship,
)
from redforge.domain.cloud_security.value_objects import (
    AccountSyncState,
    CloudAccountId,
    CloudAccountMetadata,
    CloudAccountType,
    CloudAssetId,
    CloudAssetType,
    CloudIAMPrincipalId,
    CloudPostureState,
    CloudProviderId,
    CloudProviderStatus,
    CloudProviderType,
    CredentialRef,
    DiscoveryConfig,
    IAMPrincipalType,
    NormalizedConfig,
    OrganizationId,
    PrivilegeLevel,
    ProviderMetadata,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudAccountModel,
    CloudAssetModel,
    CloudIAMPrincipalModel,
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


def asset_to_model(asset: CloudAsset, model: CloudAssetModel | None = None) -> CloudAssetModel:
    target = model or CloudAssetModel(id=asset.id.value)
    target.id = asset.id.value
    target.cloud_account_id = asset.cloud_account_id.value
    target.organization_id = str(asset.organization_id)
    target.asset_type = asset.asset_type.value
    target.provider_id = asset.provider_id
    target.region = asset.region.to_dict()
    target.availability_zone = (
        asset.availability_zone.to_dict() if asset.availability_zone is not None else None
    )
    target.display_name = asset.display_name
    target.provider_metadata = asset.provider_metadata.to_dict()
    target.normalized_config = asset.normalized_config.to_dict()
    target.tags = dict(asset.tags)
    target.relationships = [rel.to_dict() for rel in asset.relationships]
    target.posture_state = asset.posture_state.to_dict()
    target.last_seen_at = asset.last_seen_at
    target.first_seen_at = asset.first_seen_at
    target.is_deleted = asset.is_deleted
    target.deleted_at = asset.deleted_at
    target.created_at = asset.created_at
    target.updated_at = asset.updated_at
    target.row_version = asset.version
    return target


def asset_from_model(model: CloudAssetModel) -> CloudAsset:
    az_raw = model.availability_zone
    availability_zone = AvailabilityZone.from_dict(az_raw) if isinstance(az_raw, dict) else None
    rels_raw = model.relationships or []
    relationships = [
        AssetRelationship.from_dict(item) for item in rels_raw if isinstance(item, dict)
    ]
    return CloudAsset(
        id=CloudAssetId(model.id),
        cloud_account_id=CloudAccountId(model.cloud_account_id),
        organization_id=OrganizationId(model.organization_id),
        asset_type=CloudAssetType(model.asset_type),
        provider_id=model.provider_id,
        region=CloudRegion.from_dict(dict(model.region)),
        availability_zone=availability_zone,
        display_name=model.display_name,
        provider_metadata=ProviderMetadata.from_dict(dict(model.provider_metadata or {})),
        normalized_config=NormalizedConfig.from_dict(dict(model.normalized_config)),
        tags={str(k): str(v) for k, v in dict(model.tags or {}).items()},
        relationships=relationships,
        posture_state=CloudPostureState.from_dict(dict(model.posture_state)),
        last_seen_at=model.last_seen_at,
        first_seen_at=model.first_seen_at,
        is_deleted=bool(model.is_deleted),
        deleted_at=model.deleted_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
        version=model.row_version,
    )


def iam_principal_to_model(
    principal: CloudIAMPrincipal, model: CloudIAMPrincipalModel | None = None
) -> CloudIAMPrincipalModel:
    """Map domain aggregate → ORM. EffectivePermissions are never persisted."""
    target = model or CloudIAMPrincipalModel(id=principal.id.value)
    target.id = principal.id.value
    target.cloud_account_id = principal.cloud_account_id.value
    target.organization_id = str(principal.organization_id)
    target.principal_type = principal.principal_type.value
    target.provider_id = principal.provider_id
    target.display_name = principal.display_name
    target.attached_policies = [p.to_dict() for p in principal.attached_policies]
    target.trust_relationships = [t.to_dict() for t in principal.trust_relationships]
    target.privilege_level = principal.privilege_level.value
    target.is_federated = principal.is_federated
    target.is_human = principal.is_human
    target.last_activity_at = principal.last_activity_at
    target.risk_indicators = [r.to_dict() for r in principal.risk_indicators]
    target.is_disabled = principal.is_disabled
    target.is_deleted = principal.is_deleted
    target.deleted_at = principal.deleted_at
    target.last_seen_at = principal.last_seen_at
    target.first_seen_at = principal.first_seen_at
    target.created_at = principal.created_at
    target.updated_at = principal.updated_at
    target.row_version = principal.version
    return target


def iam_principal_from_model(model: CloudIAMPrincipalModel) -> CloudIAMPrincipal:
    policies_raw = model.attached_policies or []
    trusts_raw = model.trust_relationships or []
    risks_raw = model.risk_indicators or []
    return CloudIAMPrincipal(
        id=CloudIAMPrincipalId(model.id),
        cloud_account_id=CloudAccountId(model.cloud_account_id),
        organization_id=OrganizationId(model.organization_id),
        principal_type=IAMPrincipalType(model.principal_type),
        provider_id=model.provider_id,
        display_name=model.display_name,
        attached_policies=[
            PolicyAttachment.from_dict(item) for item in policies_raw if isinstance(item, dict)
        ],
        trust_relationships=[
            TrustRelationship.from_dict(item) for item in trusts_raw if isinstance(item, dict)
        ],
        privilege_level=PrivilegeLevel(model.privilege_level),
        is_federated=bool(model.is_federated),
        is_human=bool(model.is_human),
        last_activity_at=model.last_activity_at,
        risk_indicators=[
            IAMRiskIndicator.from_dict(item) for item in risks_raw if isinstance(item, dict)
        ],
        is_disabled=bool(model.is_disabled),
        is_deleted=bool(model.is_deleted),
        deleted_at=model.deleted_at,
        last_seen_at=model.last_seen_at,
        first_seen_at=model.first_seen_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
        version=model.row_version,
    )
