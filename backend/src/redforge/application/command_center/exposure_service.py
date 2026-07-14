"""Network exposure read service — M18.

Top open ports and validated services, aggregated exclusively from real
M16 `network_observations` rows. Nothing is inferred from an IP string
or a version banner; a port only appears if it was actually observed
reachable, a service only appears if a protocol validator actually
validated it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.infrastructure.database.repositories.asset_repository import (
    SqlAlchemyAssetRepository,
)
from redforge.infrastructure.database.repositories.command_center_repository import (
    SqlAlchemyNetworkExposureQueryRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class PortExposureDTO:
    port: int
    transport: str
    asset_count: int
    observation_count: int
    last_observed_at: str


@dataclass(frozen=True, slots=True)
class ServiceExposureDTO:
    service: str
    validator_id: str
    asset_count: int
    observation_count: int
    last_observed_at: str


@dataclass(frozen=True, slots=True)
class PortAssetDTO:
    asset_id: str
    observation_count: int
    last_observed_at: str
    # Real ai_assets.name — for IP/service-kind assets this literally
    # contains the dotted IP or "service (proto/port) on host" text (see
    # application/network_discovery/service.py's naming). "" if the asset
    # no longer resolves, never fabricated.
    asset_name: str = ""


class NetworkExposureService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def top_open_ports(self, organization_id: str, limit: int) -> list[PortExposureDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkExposureQueryRepository(uow.session)
            rows = await repo.top_open_ports(organization_id, limit)
        return [
            PortExposureDTO(
                port=r.port, transport=r.transport, asset_count=r.asset_count,
                observation_count=r.observation_count,
                last_observed_at=r.last_observed_at.isoformat(),
            )
            for r in rows
        ]

    async def assets_for_port(
        self, organization_id: str, port: int, limit: int, offset: int,
    ) -> list[PortAssetDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkExposureQueryRepository(uow.session)
            rows = await repo.assets_for_port(organization_id, port, limit, offset)
            asset_repo = SqlAlchemyAssetRepository(uow.session)
            dtos: list[PortAssetDTO] = []
            for r in rows:
                asset = await asset_repo.get_by_id_for_org(r.asset_id, organization_id)
                dtos.append(
                    PortAssetDTO(
                        asset_id=r.asset_id, observation_count=r.observation_count,
                        last_observed_at=r.last_observed_at.isoformat(),
                        asset_name=asset.name if asset else "",
                    )
                )
        return dtos

    async def validated_services(
        self, organization_id: str, limit: int,
    ) -> list[ServiceExposureDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyNetworkExposureQueryRepository(uow.session)
            rows = await repo.validated_services(organization_id, limit)
        return [
            ServiceExposureDTO(
                service=r.service, validator_id=r.validator_id, asset_count=r.asset_count,
                observation_count=r.observation_count,
                last_observed_at=r.last_observed_at.isoformat(),
            )
            for r in rows
        ]
