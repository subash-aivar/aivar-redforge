"""Read/CRUD repositories for the Command Center — M18.

Three repositories, all strictly organization-scoped:

  - SqlAlchemyNetworkExposureQueryRepository: aggregation-only reads over
    the existing M16 `network_observations` table (no new truth). Top
    open ports come from real `tcp_reachability` observations; validated
    services come from real `protocol_validation`/`tls_validation`
    observations. Nothing is inferred from an IP string or a version
    banner.
  - SqlAlchemyNetworkZoneRepository: CRUD over admin-authored
    `network_zone_assignments`.
  - SqlAlchemyIntegrationProviderRepository: CRUD over the
    `integration_providers` boundary descriptors.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import cast, distinct, func, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import IntegrityError

from redforge.infrastructure.database.models.command_center import (
    IntegrationProviderModel,
    NetworkZoneAssignmentModel,
)
from redforge.infrastructure.database.models.network_security import NetworkObservationModel

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class PortExposureRow:
    port: int
    transport: str
    asset_count: int
    observation_count: int
    last_observed_at: datetime


@dataclass(frozen=True, slots=True)
class ServiceExposureRow:
    service: str
    validator_id: str
    asset_count: int
    observation_count: int
    last_observed_at: datetime


@dataclass(frozen=True, slots=True)
class PortAssetRow:
    asset_id: str
    observation_count: int
    last_observed_at: datetime


# network_observations.data is a generic JSON column; `.astext` (the
# `->>` unquoted-text operator) is only available on JSONB, so cast to
# JSONB for the extraction. Built at import; executed only against
# Postgres (the exposure aggregation is Postgres-only, integration-tested).
_DATA_JSONB = cast(NetworkObservationModel.data, JSONB)
_PORT = _DATA_JSONB["port"].astext
_VALIDATED_PROTOCOL = _DATA_JSONB["validated_protocol"].astext
_VALIDATOR_ID = _DATA_JSONB["validator_id"].astext


class SqlAlchemyNetworkExposureQueryRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def top_open_ports(self, organization_id: str, limit: int) -> list[PortExposureRow]:
        """Aggregate over real `tcp_reachability` observations whose
        outcome was `reachable`. All current network observations are
        TCP (see orchestrator); transport is reported as such rather
        than fabricated. Ordered by asset breadth then volume."""
        stmt = (
            select(
                _PORT.label("port"),
                func.count(distinct(NetworkObservationModel.asset_id)).label("asset_count"),
                func.count(NetworkObservationModel.id).label("observation_count"),
                func.max(NetworkObservationModel.observed_at).label("last_observed_at"),
            )
            .where(
                NetworkObservationModel.organization_id == organization_id,
                NetworkObservationModel.observation_type == "tcp_reachability",
                NetworkObservationModel.outcome == "reachable",
            )
            .group_by(_PORT)
            .order_by(
                func.count(distinct(NetworkObservationModel.asset_id)).desc(),
                func.count(NetworkObservationModel.id).desc(),
                _PORT,
            )
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        rows: list[PortExposureRow] = []
        for r in result.all():
            try:
                port = int(r.port)
            except (TypeError, ValueError):
                continue
            rows.append(
                PortExposureRow(
                    port=port, transport="tcp", asset_count=r.asset_count,
                    observation_count=r.observation_count, last_observed_at=r.last_observed_at,
                )
            )
        return rows

    async def assets_for_port(
        self, organization_id: str, port: int, limit: int, offset: int,
    ) -> list[PortAssetRow]:
        stmt = (
            select(
                NetworkObservationModel.asset_id.label("asset_id"),
                func.count(NetworkObservationModel.id).label("observation_count"),
                func.max(NetworkObservationModel.observed_at).label("last_observed_at"),
            )
            .where(
                NetworkObservationModel.organization_id == organization_id,
                NetworkObservationModel.observation_type == "tcp_reachability",
                NetworkObservationModel.outcome == "reachable",
                _PORT == str(port),  # noqa: SIM300  (SQLAlchemy column comparison, not a Yoda check)
            )
            .group_by(NetworkObservationModel.asset_id)
            .order_by(func.max(NetworkObservationModel.observed_at).desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [
            PortAssetRow(
                asset_id=r.asset_id, observation_count=r.observation_count,
                last_observed_at=r.last_observed_at,
            )
            for r in result.all()
        ]

    async def validated_services(
        self, organization_id: str, limit: int,
    ) -> list[ServiceExposureRow]:
        """Aggregate over real `protocol_validation` observations that
        actually validated a protocol. Service identity is the
        validator-reported `validated_protocol` — never guessed from a
        port number or banner."""
        stmt = (
            select(
                _VALIDATED_PROTOCOL.label("service"),
                _VALIDATOR_ID.label("validator_id"),
                func.count(distinct(NetworkObservationModel.asset_id)).label("asset_count"),
                func.count(NetworkObservationModel.id).label("observation_count"),
                func.max(NetworkObservationModel.observed_at).label("last_observed_at"),
            )
            .where(
                NetworkObservationModel.organization_id == organization_id,
                NetworkObservationModel.observation_type == "protocol_validation",
                _VALIDATED_PROTOCOL.isnot(None),
                _VALIDATED_PROTOCOL != "",
            )
            .group_by(_VALIDATED_PROTOCOL, _VALIDATOR_ID)
            .order_by(
                func.count(distinct(NetworkObservationModel.asset_id)).desc(),
                _VALIDATED_PROTOCOL,
            )
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [
            ServiceExposureRow(
                service=r.service, validator_id=r.validator_id or "",
                asset_count=r.asset_count, observation_count=r.observation_count,
                last_observed_at=r.last_observed_at,
            )
            for r in result.all()
        ]


class SqlAlchemyNetworkZoneRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_for_asset(
        self, organization_id: str, asset_id: str,
    ) -> NetworkZoneAssignmentModel | None:
        stmt = select(NetworkZoneAssignmentModel).where(
            NetworkZoneAssignmentModel.organization_id == organization_id,
            NetworkZoneAssignmentModel.asset_id == asset_id,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_for_org(
        self, organization_id: str, zone_type: str | None, limit: int, offset: int,
    ) -> list[NetworkZoneAssignmentModel]:
        stmt = select(NetworkZoneAssignmentModel).where(
            NetworkZoneAssignmentModel.organization_id == organization_id,
        )
        if zone_type is not None:
            stmt = stmt.where(NetworkZoneAssignmentModel.zone_type == zone_type)
        stmt = stmt.order_by(NetworkZoneAssignmentModel.asset_id).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_zone(self, organization_id: str) -> dict[str, int]:
        stmt = (
            select(
                NetworkZoneAssignmentModel.zone_type,
                func.count(NetworkZoneAssignmentModel.id),
            )
            .where(NetworkZoneAssignmentModel.organization_id == organization_id)
            .group_by(NetworkZoneAssignmentModel.zone_type)
        )
        result = await self._session.execute(stmt)
        return {zone: count for zone, count in result.all()}

    async def upsert(self, model: NetworkZoneAssignmentModel) -> None:
        """Race-safe upsert on the natural key (organization_id, asset_id).

        Under concurrent first-time assignment for the same asset, both
        callers see no existing row and INSERT distinct PKs; the
        `ux_nza_org_asset` unique constraint rejects the loser. Rather
        than let that surface as an unhandled 500, the loser's
        IntegrityError is caught inside a SAVEPOINT (so the outer
        transaction survives), the winner's row is re-fetched, and this
        caller's intended values are applied in place — converging on
        exactly one row with a handled outcome. Same pattern as
        rbac_repository / SecurityConditionRepository upserts."""
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            existing = await self.get_for_asset(model.organization_id, model.asset_id)
            if existing is None:  # pragma: no cover - should be unreachable
                raise
            existing.zone_type = model.zone_type
            existing.note = model.note
            existing.assigned_by = model.assigned_by
            existing.updated_at = model.updated_at
            await self._session.flush()

    async def delete_for_asset(self, organization_id: str, asset_id: str) -> bool:
        existing = await self.get_for_asset(organization_id, asset_id)
        if existing is None:
            return False
        await self._session.delete(existing)
        await self._session.flush()
        return True


class SqlAlchemyIntegrationProviderRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_for_org(self, organization_id: str) -> list[IntegrationProviderModel]:
        stmt = select(IntegrationProviderModel).where(
            IntegrationProviderModel.organization_id == organization_id,
        )
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def get_by_type(
        self, organization_id: str, integration_type: str,
    ) -> IntegrationProviderModel | None:
        stmt = select(IntegrationProviderModel).where(
            IntegrationProviderModel.organization_id == organization_id,
            IntegrationProviderModel.integration_type == integration_type,
        )
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none()

    async def upsert(self, model: IntegrationProviderModel) -> None:
        """Race-safe upsert on the natural key (organization_id,
        integration_type) — see SqlAlchemyNetworkZoneRepository.upsert for
        the rationale. Concurrent registration of the same integration
        type converges on one descriptor with a handled outcome instead
        of an unhandled 500 from the `ux_intp_org_type` constraint."""
        try:
            async with self._session.begin_nested():
                await self._session.merge(model)
                await self._session.flush()
        except IntegrityError:
            existing = await self.get_by_type(model.organization_id, model.integration_type)
            if existing is None:  # pragma: no cover - should be unreachable
                raise
            existing.provider_name = model.provider_name
            existing.status = model.status
            existing.config = model.config
            existing.last_telemetry_at = model.last_telemetry_at
            existing.registered_by = model.registered_by
            existing.updated_at = model.updated_at
            await self._session.flush()

    async def delete_by_type(self, organization_id: str, integration_type: str) -> bool:
        existing = await self.get_by_type(organization_id, integration_type)
        if existing is None:
            return False
        await self._session.delete(existing)
        await self._session.flush()
        return True
