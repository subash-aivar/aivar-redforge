"""PostgreSQL repository implementations for CloudProvider and CloudAccount."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from redforge.domain.cloud_security.cloud_account import CloudAccount
from redforge.domain.cloud_security.cloud_provider import CloudProvider
from redforge.domain.cloud_security.exceptions import (
    CloudAccountAlreadyExistsError,
    CloudProviderAlreadyExistsError,
)
from redforge.domain.cloud_security.repositories import Page
from redforge.domain.cloud_security.value_objects import (
    CloudAccountId,
    CloudProviderId,
    CloudProviderType,
    OrganizationId,
)
from redforge.infrastructure.cloud_security.mappings.cloud_security_mapper import (
    account_from_model,
    account_to_model,
    provider_from_model,
    provider_to_model,
)
from redforge.infrastructure.database.models.cloud_security import (
    CloudAccountModel,
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
