"""PostgreSQL repository implementations for CloudProvider, CloudAccount, CloudAsset, IAM."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_asset import CloudAsset
from redforge.domain.cloud_security.cloud_iam_principal import CloudIAMPrincipal
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.exceptions import (
    CloudAccountAlreadyExistsError,
    CloudAssetAlreadyExistsError,
    CloudIAMPrincipalAlreadyExistsError,
    CloudProviderAlreadyExistsError,
)
from redforge.domain.cloud_security.repositories import Page
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudAssetId,
    CloudAssetType,
    CloudIAMPrincipalId,
    CloudProviderId,
    CloudProviderType,
    IAMPrincipalType,
    OrganizationId,
)
from redforge.infrastructure.cloud_security.mappings.cloud_security_mapper import (
    account_from_model,
    account_to_model,
    asset_from_model,
    asset_to_model,
    iam_principal_from_model,
    iam_principal_to_model,
    provider_from_model,
    provider_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudAccountModel,
    CloudAssetModel,
    CloudIAMPrincipalModel,
    CloudProviderModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PgCloudProviderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, provider: CloudProvider) -> None:
        existing = await self._session.get(CloudProviderModel, provider.id.value)
        try:
            if existing is None:
                self._session.add(provider_to_model(provider))
            else:
                provider_to_model(provider, existing)
            await self._session.flush()
        except IntegrityError as exc:
            raise CloudProviderAlreadyExistsError(
                str(provider.organization_id), provider.provider_type.value
            ) from exc

    async def get_by_id(
        self, provider_id: CloudProviderId, organization_id: OrganizationId
    ) -> CloudProvider | None:
        result = await self._session.execute(
            select(CloudProviderModel).where(
                CloudProviderModel.id == provider_id.value,
                CloudProviderModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return provider_from_model(row) if row is not None else None

    async def list_by_organization(self, org_id: OrganizationId) -> list[CloudProvider]:
        result = await self._session.execute(
            select(CloudProviderModel)
            .where(CloudProviderModel.organization_id == str(org_id))
            .order_by(CloudProviderModel.created_at.asc())
        )
        return [provider_from_model(row) for row in result.scalars().all()]

    async def get_by_org_and_type(
        self, org_id: OrganizationId, provider_type: CloudProviderType
    ) -> CloudProvider | None:
        result = await self._session.execute(
            select(CloudProviderModel).where(
                CloudProviderModel.organization_id == str(org_id),
                CloudProviderModel.provider_type == provider_type.value,
            )
        )
        row = result.scalar_one_or_none()
        return provider_from_model(row) if row is not None else None


class PgCloudAccountRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, account: CloudAccount) -> None:
        existing = await self._session.get(CloudAccountModel, account.id.value)
        try:
            if existing is None:
                self._session.add(account_to_model(account))
            else:
                account_to_model(account, existing)
            await self._session.flush()
        except IntegrityError as exc:
            raise CloudAccountAlreadyExistsError(
                str(account.cloud_provider_id), account.external_id
            ) from exc

    async def get_by_id(
        self, account_id: CloudAccountId, organization_id: OrganizationId
    ) -> CloudAccount | None:
        result = await self._session.execute(
            select(CloudAccountModel).where(
                CloudAccountModel.id == account_id.value,
                CloudAccountModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return account_from_model(row) if row is not None else None

    async def list_by_provider(
        self, provider_id: CloudProviderId, organization_id: OrganizationId
    ) -> list[CloudAccount]:
        result = await self._session.execute(
            select(CloudAccountModel)
            .where(
                CloudAccountModel.cloud_provider_id == provider_id.value,
                CloudAccountModel.organization_id == str(organization_id),
            )
            .order_by(CloudAccountModel.created_at.asc())
        )
        return [account_from_model(row) for row in result.scalars().all()]

    async def list_by_organization(
        self, org_id: OrganizationId, *, page: int, size: int
    ) -> Page[CloudAccount]:
        if page < 1:
            page = 1
        if size < 1:
            size = 20
        if size > 200:
            size = 200
        base = select(CloudAccountModel).where(CloudAccountModel.organization_id == str(org_id))
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CloudAccountModel.created_at.asc()).offset((page - 1) * size).limit(size)
        )
        items = [account_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)

    async def get_by_external_id(
        self,
        provider_type: CloudProviderType,
        external_id: str,
        org_id: OrganizationId,
    ) -> CloudAccount | None:
        result = await self._session.execute(
            select(CloudAccountModel)
            .join(
                CloudProviderModel,
                CloudProviderModel.id == CloudAccountModel.cloud_provider_id,
            )
            .where(
                CloudAccountModel.organization_id == str(org_id),
                CloudAccountModel.external_id == external_id,
                CloudProviderModel.provider_type == provider_type.value,
                CloudProviderModel.organization_id == str(org_id),
            )
        )
        row = result.scalar_one_or_none()
        return account_from_model(row) if row is not None else None


def _clamp_page(page: int, size: int) -> tuple[int, int]:
    if page < 1:
        page = 1
    if size < 1:
        size = 20
    if size > 200:
        size = 200
    return page, size


class PgCloudAssetRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, asset: CloudAsset) -> None:
        existing = await self._session.get(CloudAssetModel, asset.id.value)
        try:
            if existing is None:
                self._session.add(asset_to_model(asset))
            else:
                asset_to_model(asset, existing)
            await self._session.flush()
        except IntegrityError as exc:
            raise CloudAssetAlreadyExistsError(
                str(asset.cloud_account_id), asset.provider_id
            ) from exc

    async def save_batch(self, assets: list[CloudAsset]) -> None:
        for asset in assets:
            await self.save(asset)

    async def get_by_id(
        self, asset_id: CloudAssetId, organization_id: OrganizationId
    ) -> CloudAsset | None:
        result = await self._session.execute(
            select(CloudAssetModel).where(
                CloudAssetModel.id == asset_id.value,
                CloudAssetModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return asset_from_model(row) if row is not None else None

    async def get_by_provider_id(
        self,
        account_id: CloudAccountId,
        provider_id: str,
        organization_id: OrganizationId,
    ) -> CloudAsset | None:
        result = await self._session.execute(
            select(CloudAssetModel).where(
                CloudAssetModel.cloud_account_id == account_id.value,
                CloudAssetModel.provider_id == provider_id,
                CloudAssetModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return asset_from_model(row) if row is not None else None

    async def list_by_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        asset_type: CloudAssetType | None,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
    ) -> Page[CloudAsset]:
        page, size = _clamp_page(page, size)
        base = select(CloudAssetModel).where(
            CloudAssetModel.cloud_account_id == account_id.value,
            CloudAssetModel.organization_id == str(organization_id),
        )
        if asset_type is not None:
            base = base.where(CloudAssetModel.asset_type == asset_type.value)
        if not include_deleted:
            base = base.where(CloudAssetModel.is_deleted.is_(False))
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CloudAssetModel.created_at.asc()).offset((page - 1) * size).limit(size)
        )
        items = [asset_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)

    async def list_by_organization(
        self,
        org_id: OrganizationId,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
        cloud_account_id: CloudAccountId | None = None,
        asset_type: CloudAssetType | None = None,
    ) -> Page[CloudAsset]:
        page, size = _clamp_page(page, size)
        base = select(CloudAssetModel).where(CloudAssetModel.organization_id == str(org_id))
        if cloud_account_id is not None:
            base = base.where(CloudAssetModel.cloud_account_id == cloud_account_id.value)
        if asset_type is not None:
            base = base.where(CloudAssetModel.asset_type == asset_type.value)
        if not include_deleted:
            base = base.where(CloudAssetModel.is_deleted.is_(False))
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CloudAssetModel.created_at.asc()).offset((page - 1) * size).limit(size)
        )
        items = [asset_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)

    async def mark_deleted(
        self,
        provider_ids_seen: set[str],
        account_id: CloudAccountId,
        organization_id: OrganizationId,
    ) -> list[CloudAsset]:
        result = await self._session.execute(
            select(CloudAssetModel).where(
                CloudAssetModel.cloud_account_id == account_id.value,
                CloudAssetModel.organization_id == str(organization_id),
                CloudAssetModel.is_deleted.is_(False),
            )
        )
        deleted: list[CloudAsset] = []
        now = datetime.now(UTC)
        for row in result.scalars().all():
            if row.provider_id in provider_ids_seen:
                continue
            asset = asset_from_model(row)
            asset.mark_deleted(now=now)
            asset_to_model(asset, row)
            deleted.append(asset)
        if deleted:
            await self._session.flush()
        return deleted

    async def list_provider_ids_for_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        *,
        include_deleted: bool = False,
    ) -> dict[str, CloudAssetId]:
        stmt = select(CloudAssetModel.provider_id, CloudAssetModel.id).where(
            CloudAssetModel.cloud_account_id == account_id.value,
            CloudAssetModel.organization_id == str(organization_id),
        )
        if not include_deleted:
            stmt = stmt.where(CloudAssetModel.is_deleted.is_(False))
        result = await self._session.execute(stmt)
        return {str(provider_id): CloudAssetId(asset_id) for provider_id, asset_id in result.all()}


class PgCloudIAMPrincipalRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, principal: CloudIAMPrincipal) -> None:
        existing = await self._session.get(CloudIAMPrincipalModel, principal.id.value)
        try:
            if existing is None:
                self._session.add(iam_principal_to_model(principal))
            else:
                iam_principal_to_model(principal, existing)
            await self._session.flush()
        except IntegrityError as exc:
            raise CloudIAMPrincipalAlreadyExistsError(
                str(principal.cloud_account_id), principal.provider_id
            ) from exc

    async def save_batch(self, principals: list[CloudIAMPrincipal]) -> None:
        for principal in principals:
            await self.save(principal)

    async def get_by_id(
        self, principal_id: CloudIAMPrincipalId, organization_id: OrganizationId
    ) -> CloudIAMPrincipal | None:
        result = await self._session.execute(
            select(CloudIAMPrincipalModel).where(
                CloudIAMPrincipalModel.id == principal_id.value,
                CloudIAMPrincipalModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return iam_principal_from_model(row) if row is not None else None

    async def get_by_provider_id(
        self,
        account_id: CloudAccountId,
        provider_id: str,
        organization_id: OrganizationId,
    ) -> CloudIAMPrincipal | None:
        result = await self._session.execute(
            select(CloudIAMPrincipalModel).where(
                CloudIAMPrincipalModel.cloud_account_id == account_id.value,
                CloudIAMPrincipalModel.provider_id == provider_id,
                CloudIAMPrincipalModel.organization_id == str(organization_id),
            )
        )
        row = result.scalar_one_or_none()
        return iam_principal_from_model(row) if row is not None else None

    async def list_by_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        principal_type: IAMPrincipalType | None,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
    ) -> Page[CloudIAMPrincipal]:
        page, size = _clamp_page(page, size)
        base = select(CloudIAMPrincipalModel).where(
            CloudIAMPrincipalModel.cloud_account_id == account_id.value,
            CloudIAMPrincipalModel.organization_id == str(organization_id),
        )
        if principal_type is not None:
            base = base.where(CloudIAMPrincipalModel.principal_type == principal_type.value)
        if not include_deleted:
            base = base.where(CloudIAMPrincipalModel.is_deleted.is_(False))
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CloudIAMPrincipalModel.created_at.asc())
            .offset((page - 1) * size)
            .limit(size)
        )
        items = [iam_principal_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)

    async def list_by_organization(
        self,
        org_id: OrganizationId,
        *,
        page: int,
        size: int,
        include_deleted: bool = False,
        cloud_account_id: CloudAccountId | None = None,
        principal_type: IAMPrincipalType | None = None,
    ) -> Page[CloudIAMPrincipal]:
        page, size = _clamp_page(page, size)
        base = select(CloudIAMPrincipalModel).where(
            CloudIAMPrincipalModel.organization_id == str(org_id)
        )
        if cloud_account_id is not None:
            base = base.where(CloudIAMPrincipalModel.cloud_account_id == cloud_account_id.value)
        if principal_type is not None:
            base = base.where(CloudIAMPrincipalModel.principal_type == principal_type.value)
        if not include_deleted:
            base = base.where(CloudIAMPrincipalModel.is_deleted.is_(False))
        total = int(
            (
                await self._session.execute(select(func.count()).select_from(base.subquery()))
            ).scalar_one()
        )
        result = await self._session.execute(
            base.order_by(CloudIAMPrincipalModel.created_at.asc())
            .offset((page - 1) * size)
            .limit(size)
        )
        items = [iam_principal_from_model(row) for row in result.scalars().all()]
        return Page(items=items, page=page, size=size, total=total)

    async def mark_deleted(
        self,
        provider_ids_seen: set[str],
        account_id: CloudAccountId,
        organization_id: OrganizationId,
    ) -> list[CloudIAMPrincipal]:
        result = await self._session.execute(
            select(CloudIAMPrincipalModel).where(
                CloudIAMPrincipalModel.cloud_account_id == account_id.value,
                CloudIAMPrincipalModel.organization_id == str(organization_id),
                CloudIAMPrincipalModel.is_deleted.is_(False),
            )
        )
        deleted: list[CloudIAMPrincipal] = []
        now = datetime.now(UTC)
        for row in result.scalars().all():
            if row.provider_id in provider_ids_seen:
                continue
            principal = iam_principal_from_model(row)
            principal.mark_deleted(now=now)
            iam_principal_to_model(principal, row)
            deleted.append(principal)
        if deleted:
            await self._session.flush()
        return deleted

    async def list_provider_ids_for_account(
        self,
        account_id: CloudAccountId,
        organization_id: OrganizationId,
        *,
        include_deleted: bool = False,
    ) -> dict[str, CloudIAMPrincipalId]:
        stmt = select(CloudIAMPrincipalModel.provider_id, CloudIAMPrincipalModel.id).where(
            CloudIAMPrincipalModel.cloud_account_id == account_id.value,
            CloudIAMPrincipalModel.organization_id == str(organization_id),
        )
        if not include_deleted:
            stmt = stmt.where(CloudIAMPrincipalModel.is_deleted.is_(False))
        result = await self._session.execute(stmt)
        return {
            str(provider_id): CloudIAMPrincipalId(principal_id)
            for provider_id, principal_id in result.all()
        }
