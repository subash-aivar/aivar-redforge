"""Orchestrates Phase 2 cloud asset discovery, upsert, and inventory projection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from redforge.application.cloud_security.asset_normalization_service import (
    AssetNormalizationService,
)
from redforge.application.cloud_security.discovery_dtos import (
    AssetRelationshipDTO,
    CloudAssetDTO,
    CloudAssetPageDTO,
    DiscoveryResultDTO,
    GetCloudAssetQuery,
    ListAssetRelationshipsQuery,
    ListCloudAssetsQuery,
    TriggerAssetDiscoveryCommand,
)
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.entities import AvailabilityZone, CloudRegion
from redforge.domain.cloud_security.exceptions import (
    CloudAccountNotFoundError,
    CloudAssetNotFoundError,
    CloudProviderDisabledError,
    CloudProviderNotFoundError,
    InvalidCloudArgumentError,
)
from redforge.domain.cloud_security.value_objects import (
    DISCOVERY_ASSET_TYPES_BY_PROVIDER,
    CloudAccountId,
    CloudAssetId,
    CloudAssetType,
    CloudProviderStatus,
    CloudProviderType,
    OrganizationId,
    ProviderMetadata,
)
from redforge.infrastructure.cloud_security.adapters.aws import AWSCloudProviderAdapter
from redforge.infrastructure.cloud_security.adapters.azure import AzureCloudProviderAdapter
from redforge.infrastructure.cloud_security.adapters.gcp import GCPCloudProviderAdapter

if TYPE_CHECKING:
    from collections.abc import Callable
    from contextlib import AbstractAsyncContextManager

    from sqlalchemy.ext.asyncio import AsyncSession

    from redforge.application.cloud_security.discovery_client_factory import (
        DiscoveryClientFactory,
    )
    from redforge.application.cloud_security.inventory_projection_service import (
        InventoryProjectionService,
    )
    from redforge.domain.cloud_security.ports import CloudProviderAdapter
    from redforge.domain.cloud_security.repositories import (
        CloudAccountRepository,
        CloudAssetRepository,
        CloudProviderRepository,
    )

    SessionFactory = Callable[[], AbstractAsyncContextManager[AsyncSession]]
    ProviderRepoFactory = Callable[[AsyncSession], CloudProviderRepository]
    AccountRepoFactory = Callable[[AsyncSession], CloudAccountRepository]
    AssetRepoFactory = Callable[[AsyncSession], CloudAssetRepository]
    AdapterBuilder = Callable[[CloudProviderType, Any], CloudProviderAdapter]


def _default_adapter(provider_type: CloudProviderType, client: Any) -> CloudProviderAdapter:
    if provider_type is CloudProviderType.AWS:
        return AWSCloudProviderAdapter(client)
    if provider_type is CloudProviderType.AZURE:
        return AzureCloudProviderAdapter(client)
    if provider_type is CloudProviderType.GCP:
        return GCPCloudProviderAdapter(client)
    raise InvalidCloudArgumentError("provider_type", f"unsupported: {provider_type}")


def _relationship_dto(rel: Any) -> AssetRelationshipDTO:
    return AssetRelationshipDTO(
        relationship_id=rel.relationship_id,
        relationship_type=rel.relationship_type.value,
        target_provider_id=rel.target_provider_id,
        target_asset_id=str(rel.target_asset_id) if rel.target_asset_id else None,
    )


def _asset_dto(asset: CloudAsset, *, include_detail: bool = False) -> CloudAssetDTO:
    return CloudAssetDTO(
        asset_id=str(asset.id),
        cloud_account_id=str(asset.cloud_account_id),
        organization_id=str(asset.organization_id),
        asset_type=asset.asset_type.value,
        provider_id=asset.provider_id,
        display_name=asset.display_name,
        region_code=asset.region.region_code,
        az_name=asset.availability_zone.name if asset.availability_zone else None,
        tags=dict(asset.tags),
        config_hash=asset.posture_state.config_hash,
        is_deleted=asset.is_deleted,
        last_seen_at=asset.last_seen_at,
        first_seen_at=asset.first_seen_at,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        version=asset.version,
        relationships=[_relationship_dto(r) for r in asset.relationships],
        normalized_config=asset.normalized_config.to_dict() if include_detail else {},
        provider_metadata=asset.provider_metadata.to_dict() if include_detail else {},
    )


def _region_for(
    region_code: str, az_name: str | None
) -> tuple[CloudRegion, AvailabilityZone | None]:
    code = region_code or "global"
    region = CloudRegion(region_code=code, display_name=code)
    az = AvailabilityZone(name=az_name, region_code=code) if az_name else None
    return region, az


class AssetDiscoveryService:
    """Phase 2 application service: discover, upsert, soft-delete, project, query."""

    def __init__(
        self,
        session_factory: SessionFactory,
        provider_repo_factory: ProviderRepoFactory,
        account_repo_factory: AccountRepoFactory,
        asset_repo_factory: AssetRepoFactory,
        client_factory: DiscoveryClientFactory,
        inventory_projection: InventoryProjectionService | None = None,
        normalization_service: AssetNormalizationService | None = None,
        adapter_builder: AdapterBuilder | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._provider_repo_factory = provider_repo_factory
        self._account_repo_factory = account_repo_factory
        self._asset_repo_factory = asset_repo_factory
        self._client_factory = client_factory
        self._inventory_projection = inventory_projection
        self._normalization = normalization_service or AssetNormalizationService()
        self._adapter_builder = adapter_builder or _default_adapter

    async def discover_account(self, command: TriggerAssetDiscoveryCommand) -> DiscoveryResultDTO:
        org = OrganizationId(command.organization_id)
        account_id = CloudAccountId.from_string(command.cloud_account_id)

        async with self._session_factory() as session, session.begin():
            providers = self._provider_repo_factory(session)
            accounts = self._account_repo_factory(session)
            account = await accounts.get_by_id(account_id, org)
            if account is None:
                raise CloudAccountNotFoundError(command.cloud_account_id)
            provider = await providers.get_by_id(account.cloud_provider_id, org)
            if provider is None:
                raise CloudProviderNotFoundError(str(account.cloud_provider_id))
            if provider.status is CloudProviderStatus.DISABLED:
                raise CloudProviderDisabledError(str(provider.id))
            account.mark_sync_started()
            await accounts.save(account)
            account.pop_events()
            provider_type = provider.provider_type
            credential_ref = account.credential_ref
            asset_types = self._resolve_asset_types(command.asset_types, provider_type)

        discovered = updated = resurrected = deleted = projected = 0
        try:
            async with self._session_factory() as session, session.begin():
                providers = self._provider_repo_factory(session)
                accounts = self._account_repo_factory(session)
                assets = self._asset_repo_factory(session)
                account = await accounts.get_by_id(account_id, org)
                if account is None:
                    raise CloudAccountNotFoundError(command.cloud_account_id)
                provider = await providers.get_by_id(account.cloud_provider_id, org)
                if provider is None:
                    raise CloudProviderNotFoundError(str(account.cloud_provider_id))

                client = self._client_factory.create(provider_type, credential_ref)
                adapter = self._adapter_builder(provider_type, client)

                seen_provider_ids: set[str] = set()
                upserted: list[CloudAsset] = []

                async for raw in adapter.list_assets(account, asset_types):
                    draft = self._normalization.normalize(raw)
                    seen_provider_ids.add(draft.provider_id)
                    region, az = _region_for(draft.region_code, draft.az_name)
                    metadata = ProviderMetadata.from_dict(draft.provider_metadata)
                    existing = await assets.get_by_provider_id(account.id, draft.provider_id, org)
                    if existing is None:
                        asset = CloudAsset.discover(
                            cloud_account_id=account.id,
                            organization_id=org,
                            asset_type=draft.asset_type,
                            provider_id=draft.provider_id,
                            region=region,
                            display_name=draft.display_name,
                            provider_metadata=metadata,
                            normalized_config=draft.normalized_config,
                            tags=draft.tags,
                            availability_zone=az,
                            relationships=draft.relationships,
                        )
                        discovered += 1
                    elif existing.is_deleted:
                        existing.resurrect_from_discovery(
                            display_name=draft.display_name,
                            provider_metadata=metadata,
                            normalized_config=draft.normalized_config,
                            tags=draft.tags,
                            region=region,
                            availability_zone=az,
                            relationships=draft.relationships,
                        )
                        asset = existing
                        resurrected += 1
                    else:
                        existing.apply_discovery(
                            display_name=draft.display_name,
                            provider_metadata=metadata,
                            normalized_config=draft.normalized_config,
                            tags=draft.tags,
                            region=region,
                            availability_zone=az,
                            relationships=draft.relationships,
                        )
                        asset = existing
                        updated += 1
                    await assets.save(asset)
                    asset.pop_events()
                    upserted.append(asset)

                provider_id_map = await assets.list_provider_ids_for_account(
                    account.id, org, include_deleted=False
                )
                for asset in upserted:
                    asset.resolve_relationship_targets(provider_id_map)
                    await assets.save(asset)
                    asset.pop_events()

                deleted_assets = await assets.mark_deleted(seen_provider_ids, account.id, org)
                deleted = len(deleted_assets)
                for deleted_asset in deleted_assets:
                    deleted_asset.pop_events()

                if self._inventory_projection is not None:
                    for asset in upserted:
                        if asset.is_deleted:
                            continue
                        await self._inventory_projection.project(
                            asset=asset, account=account, provider=provider
                        )
                        projected += 1

                account.mark_sync_completed()
                await accounts.save(account)
                account.pop_events()
                return DiscoveryResultDTO(
                    cloud_account_id=str(account.id),
                    organization_id=str(org),
                    sync_status=account.sync_state.status.value,
                    discovered_count=discovered,
                    updated_count=updated,
                    resurrected_count=resurrected,
                    deleted_count=deleted,
                    projected_count=projected,
                )
        except Exception as exc:
            async with self._session_factory() as session, session.begin():
                accounts = self._account_repo_factory(session)
                account = await accounts.get_by_id(account_id, org)
                if account is not None:
                    account.mark_sync_failed(str(exc)[:512])
                    await accounts.save(account)
                    account.pop_events()
            raise

    def _resolve_asset_types(
        self, requested: tuple[str, ...], provider_type: CloudProviderType
    ) -> list[CloudAssetType]:
        if not requested:
            return list(DISCOVERY_ASSET_TYPES_BY_PROVIDER[provider_type])
        types: list[CloudAssetType] = []
        for raw in requested:
            try:
                types.append(CloudAssetType(raw.upper()))
            except ValueError as exc:
                raise InvalidCloudArgumentError("asset_types", f"unknown type: {raw}") from exc
        return types

    async def list_cloud_assets(self, query: ListCloudAssetsQuery) -> CloudAssetPageDTO:
        org = OrganizationId(query.organization_id)
        asset_type = None
        if query.asset_type:
            try:
                asset_type = CloudAssetType(query.asset_type.upper())
            except ValueError as exc:
                raise InvalidCloudArgumentError(
                    "asset_type", f"unknown type: {query.asset_type}"
                ) from exc
        account_id = (
            CloudAccountId.from_string(query.cloud_account_id) if query.cloud_account_id else None
        )
        async with self._session_factory() as session:
            assets = self._asset_repo_factory(session)
            page = await assets.list_by_organization(
                org,
                page=query.page,
                size=query.size,
                include_deleted=query.include_deleted,
                cloud_account_id=account_id,
                asset_type=asset_type,
            )
            return CloudAssetPageDTO(
                items=[_asset_dto(item) for item in page.items],
                page=page.page,
                size=page.size,
                total=page.total,
            )

    async def get_cloud_asset(self, query: GetCloudAssetQuery) -> CloudAssetDTO:
        org = OrganizationId(query.organization_id)
        asset_id = CloudAssetId.from_string(query.asset_id)
        async with self._session_factory() as session:
            assets = self._asset_repo_factory(session)
            asset = await assets.get_by_id(asset_id, org)
            if asset is None:
                raise CloudAssetNotFoundError(query.asset_id)
            return _asset_dto(asset, include_detail=True)

    async def list_asset_relationships(
        self, query: ListAssetRelationshipsQuery
    ) -> list[AssetRelationshipDTO]:
        org = OrganizationId(query.organization_id)
        asset_id = CloudAssetId.from_string(query.asset_id)
        async with self._session_factory() as session:
            assets = self._asset_repo_factory(session)
            asset = await assets.get_by_id(asset_id, org)
            if asset is None:
                raise CloudAssetNotFoundError(query.asset_id)
            return [_relationship_dto(r) for r in asset.relationships]
