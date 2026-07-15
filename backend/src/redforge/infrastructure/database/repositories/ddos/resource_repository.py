"""Protected resource and detection policy repositories — M19."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.ddos import (
    DDoSDetectionPolicyModel,
    DDoSProtectedResourceModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyProtectedResourceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(
        self, organization_id: str, resource_id: str
    ) -> DDoSProtectedResourceModel | None:
        stmt = select(DDoSProtectedResourceModel).where(
            DDoSProtectedResourceModel.organization_id == organization_id,
            DDoSProtectedResourceModel.id == resource_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_for_org(
        self, organization_id: str, enabled_only: bool = False
    ) -> list[DDoSProtectedResourceModel]:
        stmt = select(DDoSProtectedResourceModel).where(
            DDoSProtectedResourceModel.organization_id == organization_id,
        )
        if enabled_only:
            stmt = stmt.where(DDoSProtectedResourceModel.monitoring_enabled.is_(True))
        stmt = stmt.order_by(DDoSProtectedResourceModel.created_at.asc())
        return list((await self._session.execute(stmt)).scalars().all())

    async def create(
        self, model: DDoSProtectedResourceModel
    ) -> DDoSProtectedResourceModel:
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model
        except IntegrityError:
            existing = await self._get_by_name(model.organization_id, model.name)
            if existing is None:
                raise
            return existing

    async def update(
        self, model: DDoSProtectedResourceModel
    ) -> DDoSProtectedResourceModel:
        model.updated_at = datetime.now(UTC)
        await self._session.flush()
        return model

    async def delete(self, organization_id: str, resource_id: str) -> bool:
        model = await self.get_by_id(organization_id, resource_id)
        if model is None:
            return False
        await self._session.delete(model)
        await self._session.flush()
        return True

    async def _get_by_name(
        self, organization_id: str, name: str
    ) -> DDoSProtectedResourceModel | None:
        stmt = select(DDoSProtectedResourceModel).where(
            DDoSProtectedResourceModel.organization_id == organization_id,
            DDoSProtectedResourceModel.name == name,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()


class SqlAlchemyDetectionPolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_resource(
        self, organization_id: str, resource_id: str
    ) -> DDoSDetectionPolicyModel | None:
        stmt = select(DDoSDetectionPolicyModel).where(
            DDoSDetectionPolicyModel.organization_id == organization_id,
            DDoSDetectionPolicyModel.resource_id == resource_id,
        )
        return (await self._session.execute(stmt)).scalar_one_or_none()

    async def list_enabled_for_org(
        self, organization_id: str
    ) -> list[DDoSDetectionPolicyModel]:
        stmt = (
            select(DDoSDetectionPolicyModel)
            .where(
                DDoSDetectionPolicyModel.organization_id == organization_id,
                DDoSDetectionPolicyModel.enabled.is_(True),
            )
        )
        return list((await self._session.execute(stmt)).scalars().all())

    async def upsert(
        self, model: DDoSDetectionPolicyModel
    ) -> DDoSDetectionPolicyModel:
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model
        except IntegrityError:
            existing = await self.get_by_resource(model.organization_id, model.resource_id)
            if existing is None:
                raise
            # Update fields
            existing.enabled = model.enabled
            existing.profile = model.profile
            existing.static_bps_threshold = model.static_bps_threshold
            existing.static_pps_threshold = model.static_pps_threshold
            existing.static_fps_threshold = model.static_fps_threshold
            existing.window_seconds = model.window_seconds
            existing.min_breach_windows = model.min_breach_windows
            existing.quiet_period_windows = model.quiet_period_windows
            existing.mitigation_mode = model.mitigation_mode
            existing.suppression_windows = model.suppression_windows
            existing.updated_at = datetime.now(UTC)
            await self._session.flush()
            return existing
