"""Repositories for the Threat Intelligence bounded context — M18
expansion pass. Same conventions as command_center_repository.py:
strictly organization-scoped, SAVEPOINT + refetch-and-converge for
concurrent upserts (rbac_repository/SecurityConditionRepository pattern).
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.threat_intel import (
    ThreatIntelEnrichmentModel,
    ThreatIntelIndicatorModel,
    ThreatIntelProviderModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyThreatIntelProviderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_name(
        self,
        organization_id: str,
        provider_name: str,
    ) -> ThreatIntelProviderModel | None:
        stmt = select(ThreatIntelProviderModel).where(
            ThreatIntelProviderModel.organization_id == organization_id,
            ThreatIntelProviderModel.provider_name == provider_name,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_org(self, organization_id: str) -> list[ThreatIntelProviderModel]:
        stmt = select(ThreatIntelProviderModel).where(
            ThreatIntelProviderModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def upsert(self, model: ThreatIntelProviderModel) -> None:
        """Race-safe upsert on (organization_id, provider_name) — same
        SAVEPOINT + refetch pattern as SqlAlchemyIntegrationProviderRepository."""
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            existing = await self.get_by_name(model.organization_id, model.provider_name)
            if existing is None:  # pragma: no cover - should be unreachable
                raise
            existing.enabled = model.enabled
            existing.allowed_indicator_types = model.allowed_indicator_types
            existing.credential_ref = model.credential_ref
            existing.config = model.config
            existing.updated_by = model.updated_by
            existing.updated_at = model.updated_at
            await self._session.flush()


class SqlAlchemyThreatIntelIndicatorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_natural_key(
        self,
        organization_id: str,
        indicator_type: str,
        indicator: str,
    ) -> ThreatIntelIndicatorModel | None:
        stmt = select(ThreatIntelIndicatorModel).where(
            ThreatIntelIndicatorModel.organization_id == organization_id,
            ThreatIntelIndicatorModel.indicator_type == indicator_type,
            ThreatIntelIndicatorModel.indicator == indicator,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_or_create(
        self,
        indicator_id: str,
        organization_id: str,
        indicator_type: str,
        indicator: str,
        now: datetime,
    ) -> ThreatIntelIndicatorModel:
        """Race-safe get-or-create keyed on the natural key. Updates
        `last_seen_at` on every observation, never invents `first_seen_at`."""
        existing = await self.get_by_natural_key(organization_id, indicator_type, indicator)
        if existing is not None:
            existing.last_seen_at = now
            await self._session.flush()
            return existing

        model = ThreatIntelIndicatorModel(
            id=indicator_id,
            organization_id=organization_id,
            indicator=indicator,
            indicator_type=indicator_type,
            first_seen_at=now,
            last_seen_at=now,
        )
        try:
            async with self._session.begin_nested():
                self._session.add(model)
                await self._session.flush()
            return model
        except IntegrityError:
            winner = await self.get_by_natural_key(organization_id, indicator_type, indicator)
            if winner is None:  # pragma: no cover - should be unreachable
                raise
            winner.last_seen_at = now
            await self._session.flush()
            return winner

    async def list_recent(
        self,
        organization_id: str,
        limit: int,
        offset: int,
    ) -> list[ThreatIntelIndicatorModel]:
        stmt = (
            select(ThreatIntelIndicatorModel)
            .where(ThreatIntelIndicatorModel.organization_id == organization_id)
            .order_by(ThreatIntelIndicatorModel.last_seen_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())


class SqlAlchemyThreatIntelEnrichmentRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_latest(
        self,
        organization_id: str,
        indicator_id: str,
        provider_name: str,
        kind: str,
    ) -> ThreatIntelEnrichmentModel | None:
        stmt = select(ThreatIntelEnrichmentModel).where(
            ThreatIntelEnrichmentModel.organization_id == organization_id,
            ThreatIntelEnrichmentModel.indicator_id == indicator_id,
            ThreatIntelEnrichmentModel.provider_name == provider_name,
            ThreatIntelEnrichmentModel.kind == kind,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_indicator(
        self,
        organization_id: str,
        indicator_id: str,
    ) -> list[ThreatIntelEnrichmentModel]:
        stmt = select(ThreatIntelEnrichmentModel).where(
            ThreatIntelEnrichmentModel.organization_id == organization_id,
            ThreatIntelEnrichmentModel.indicator_id == indicator_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_recent_for_org(
        self,
        organization_id: str,
        limit: int,
    ) -> list[ThreatIntelEnrichmentModel]:
        stmt = (
            select(ThreatIntelEnrichmentModel)
            .where(ThreatIntelEnrichmentModel.organization_id == organization_id)
            .order_by(ThreatIntelEnrichmentModel.fetched_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_recent_for_provider(
        self,
        organization_id: str,
        provider_name: str,
        limit: int,
    ) -> list[ThreatIntelEnrichmentModel]:
        stmt = (
            select(ThreatIntelEnrichmentModel)
            .where(
                ThreatIntelEnrichmentModel.organization_id == organization_id,
                ThreatIntelEnrichmentModel.provider_name == provider_name,
            )
            .order_by(ThreatIntelEnrichmentModel.fetched_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_geo_enrichments_for_org(
        self,
        organization_id: str,
        limit: int = 500,
    ) -> list[tuple[ThreatIntelIndicatorModel, ThreatIntelEnrichmentModel]]:
        """Returns (indicator, enrichment) pairs for IP indicators that have
        at least one geolocation or asn_rdap enrichment. Used to power the
        geographic security activity map — only real enriched indicators, never
        fabricated points."""
        from sqlalchemy import and_, or_

        stmt = (
            select(ThreatIntelIndicatorModel, ThreatIntelEnrichmentModel)
            .join(
                ThreatIntelEnrichmentModel,
                and_(
                    ThreatIntelEnrichmentModel.indicator_id == ThreatIntelIndicatorModel.id,
                    ThreatIntelEnrichmentModel.organization_id
                    == ThreatIntelIndicatorModel.organization_id,
                ),
            )
            .where(
                ThreatIntelIndicatorModel.organization_id == organization_id,
                ThreatIntelIndicatorModel.indicator_type == "ip",
                ThreatIntelEnrichmentModel.success.is_(True),
                or_(
                    ThreatIntelEnrichmentModel.kind == "geolocation",
                    ThreatIntelEnrichmentModel.kind == "asn_rdap",
                ),
            )
            .order_by(ThreatIntelIndicatorModel.last_seen_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return list(result.all())

    async def upsert(self, model: ThreatIntelEnrichmentModel) -> ThreatIntelEnrichmentModel:
        """Race-safe upsert on (organization_id, indicator_id,
        provider_name, kind) — same SAVEPOINT + refetch pattern used
        throughout this codebase."""
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
            return model
        except IntegrityError:
            existing = await self.get_latest(
                model.organization_id,
                model.indicator_id,
                model.provider_name,
                model.kind,
            )
            if existing is None:  # pragma: no cover - should be unreachable
                raise
            existing.success = model.success
            existing.error_category = model.error_category
            existing.data = model.data
            existing.detail = model.detail
            existing.fetched_at = model.fetched_at
            existing.expires_at = model.expires_at
            await self._session.flush()
            return existing
