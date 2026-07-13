"""DirectorySecurityRepository — M5.

Idempotent upsert semantics mirroring the M3 asset / M4 graph
repository pattern: canonical identity is a tenant+connector-scoped
unique constraint, not the row's own primary key. Concurrent
resolution of the same (organization_id, connector_id, external_id)
converges on one row via select-then-insert-with-IntegrityError-
fallback-to-refetch, never a duplicate.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.directory_security import (
    DirectoryGroupModel,
    DirectoryIdentityModel,
    DirectoryMembershipModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class DirectorySecurityRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def upsert_identity(
        self,
        identity_id: str,
        organization_id: str,
        connector_id: str,
        external_id: str,
        principal_category: str,
        display_name: str,
        principal_name: str,
        source_enabled: bool,
        privilege_classification: str,
        privilege_reason: str,
        observation_lifecycle: str,
        safe_attributes: dict[str, str],
    ) -> DirectoryIdentityModel:
        existing = await self._get_identity_by_source(organization_id, connector_id, external_id)
        now = datetime.now(UTC)
        if existing is not None:
            existing.principal_category = principal_category
            existing.display_name = display_name
            existing.principal_name = principal_name
            existing.source_enabled = source_enabled
            existing.privilege_classification = privilege_classification
            existing.privilege_reason = privilege_reason
            existing.observation_lifecycle = observation_lifecycle
            existing.safe_attributes = safe_attributes
            existing.last_observed_at = now
            existing.version += 1
            await self._session.flush()
            return existing

        model = DirectoryIdentityModel(
            id=identity_id,
            organization_id=organization_id,
            connector_id=connector_id,
            external_id=external_id,
            principal_category=principal_category,
            display_name=display_name,
            principal_name=principal_name,
            source_enabled=source_enabled,
            privilege_classification=privilege_classification,
            privilege_reason=privilege_reason,
            observation_lifecycle=observation_lifecycle,
            safe_attributes=safe_attributes,
            first_observed_at=now,
            last_observed_at=now,
            version=1,
        )
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            winner = await self._get_identity_by_source(organization_id, connector_id, external_id)
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.display_name = display_name
            winner.principal_name = principal_name
            winner.source_enabled = source_enabled
            winner.privilege_classification = privilege_classification
            winner.privilege_reason = privilege_reason
            winner.safe_attributes = safe_attributes
            winner.last_observed_at = now
            winner.version += 1
            await self._session.flush()
            return winner
        return model

    async def upsert_group(
        self,
        group_id: str,
        organization_id: str,
        connector_id: str,
        external_id: str,
        display_name: str,
        is_recognized_privileged: bool,
    ) -> DirectoryGroupModel:
        existing = await self._get_group_by_source(organization_id, connector_id, external_id)
        now = datetime.now(UTC)
        if existing is not None:
            existing.display_name = display_name
            existing.is_recognized_privileged = is_recognized_privileged
            existing.last_observed_at = now
            existing.version += 1
            await self._session.flush()
            return existing

        model = DirectoryGroupModel(
            id=group_id,
            organization_id=organization_id,
            connector_id=connector_id,
            external_id=external_id,
            display_name=display_name,
            is_recognized_privileged=is_recognized_privileged,
            first_observed_at=now,
            last_observed_at=now,
            version=1,
        )
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            winner = await self._get_group_by_source(organization_id, connector_id, external_id)
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.display_name = display_name
            winner.is_recognized_privileged = is_recognized_privileged
            winner.last_observed_at = now
            winner.version += 1
            await self._session.flush()
            return winner
        return model

    async def upsert_membership(
        self,
        membership_id: str,
        organization_id: str,
        identity_id: str,
        group_id: str,
        provenance: str,
    ) -> DirectoryMembershipModel:
        existing = await self._get_membership(organization_id, identity_id, group_id)
        now = datetime.now(UTC)
        if existing is not None:
            existing.last_observed_at = now
            existing.version += 1
            await self._session.flush()
            return existing

        model = DirectoryMembershipModel(
            id=membership_id,
            organization_id=organization_id,
            identity_id=identity_id,
            group_id=group_id,
            provenance=provenance,
            first_observed_at=now,
            last_observed_at=now,
            version=1,
        )
        self._session.add(model)
        try:
            await self._session.flush()
        except IntegrityError:
            await self._session.rollback()
            winner = await self._get_membership(organization_id, identity_id, group_id)
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.last_observed_at = now
            winner.version += 1
            await self._session.flush()
            return winner
        return model

    async def _get_identity_by_source(
        self, organization_id: str, connector_id: str, external_id: str
    ) -> DirectoryIdentityModel | None:
        stmt = select(DirectoryIdentityModel).where(
            DirectoryIdentityModel.organization_id == organization_id,
            DirectoryIdentityModel.connector_id == connector_id,
            DirectoryIdentityModel.external_id == external_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_group_by_source(
        self, organization_id: str, connector_id: str, external_id: str
    ) -> DirectoryGroupModel | None:
        stmt = select(DirectoryGroupModel).where(
            DirectoryGroupModel.organization_id == organization_id,
            DirectoryGroupModel.connector_id == connector_id,
            DirectoryGroupModel.external_id == external_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def _get_membership(
        self, organization_id: str, identity_id: str, group_id: str
    ) -> DirectoryMembershipModel | None:
        stmt = select(DirectoryMembershipModel).where(
            DirectoryMembershipModel.organization_id == organization_id,
            DirectoryMembershipModel.identity_id == identity_id,
            DirectoryMembershipModel.group_id == group_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_identity_by_id_for_org(
        self, identity_id: str, organization_id: str
    ) -> DirectoryIdentityModel | None:
        stmt = select(DirectoryIdentityModel).where(
            DirectoryIdentityModel.id == identity_id,
            DirectoryIdentityModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_group_by_id_for_org(
        self, group_id: str, organization_id: str
    ) -> DirectoryGroupModel | None:
        stmt = select(DirectoryGroupModel).where(
            DirectoryGroupModel.id == group_id,
            DirectoryGroupModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_identities_for_org(
        self,
        organization_id: str,
        principal_category: str | None = None,
        privilege_classification: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[DirectoryIdentityModel]:
        stmt = select(DirectoryIdentityModel).where(
            DirectoryIdentityModel.organization_id == organization_id
        )
        if principal_category is not None:
            stmt = stmt.where(DirectoryIdentityModel.principal_category == principal_category)
        if privilege_classification is not None:
            stmt = stmt.where(
                DirectoryIdentityModel.privilege_classification == privilege_classification
            )
        stmt = stmt.order_by(DirectoryIdentityModel.id).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_groups_for_org(
        self, organization_id: str, limit: int = 100, offset: int = 0
    ) -> list[DirectoryGroupModel]:
        stmt = (
            select(DirectoryGroupModel)
            .where(DirectoryGroupModel.organization_id == organization_id)
            .order_by(DirectoryGroupModel.id)
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_direct_memberships_for_identity(
        self, organization_id: str, identity_id: str
    ) -> list[DirectoryMembershipModel]:
        stmt = select(DirectoryMembershipModel).where(
            DirectoryMembershipModel.organization_id == organization_id,
            DirectoryMembershipModel.identity_id == identity_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_direct_members_for_group(
        self, organization_id: str, group_id: str
    ) -> list[DirectoryMembershipModel]:
        stmt = select(DirectoryMembershipModel).where(
            DirectoryMembershipModel.organization_id == organization_id,
            DirectoryMembershipModel.group_id == group_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())
