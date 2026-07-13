"""SqlAlchemy repository for the durable, append-only NetworkObservation
log (M16). Never update()/delete() — an observation is a fact about a
point in time, never mutated in place.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.database.models.network_security import NetworkObservationModel
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class NetworkObservationRow:
    id: str
    organization_id: str
    run_id: str
    asset_id: str
    observation_type: str
    method: str
    outcome: str
    schema_version: int
    data: dict[str, Any]
    observed_at: datetime


def _to_row(model: NetworkObservationModel) -> NetworkObservationRow:
    return NetworkObservationRow(
        id=model.id, organization_id=model.organization_id, run_id=model.run_id,
        asset_id=model.asset_id, observation_type=model.observation_type,
        method=model.method, outcome=model.outcome, schema_version=model.schema_version,
        data=model.data, observed_at=model.observed_at,
    )


class SqlAlchemyNetworkObservationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def append(
        self,
        *,
        organization_id: str,
        run_id: str,
        asset_id: str,
        observation_type: str,
        method: str,
        outcome: str,
        data: dict[str, Any],
        observed_at: datetime,
        schema_version: int = 1,
    ) -> None:
        self._session.add(
            NetworkObservationModel(
                id=str(EntityId.generate()), organization_id=organization_id, run_id=run_id,
                asset_id=asset_id, observation_type=observation_type, method=method,
                outcome=outcome, schema_version=schema_version, data=data,
                observed_at=observed_at,
            )
        )
        await self._session.flush()

    async def list_for_asset(
        self, organization_id: str, asset_id: str, limit: int = 100,
    ) -> list[NetworkObservationRow]:
        stmt = (
            select(NetworkObservationModel)
            .where(
                NetworkObservationModel.organization_id == organization_id,
                NetworkObservationModel.asset_id == asset_id,
            )
            .order_by(NetworkObservationModel.observed_at.desc())
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_to_row(m) for m in result.scalars().all()]

    async def list_for_run(
        self, organization_id: str, run_id: str, limit: int = 500,
    ) -> list[NetworkObservationRow]:
        stmt = (
            select(NetworkObservationModel)
            .where(
                NetworkObservationModel.organization_id == organization_id,
                NetworkObservationModel.run_id == run_id,
            )
            .order_by(NetworkObservationModel.observed_at)
            .limit(limit)
        )
        result = await self._session.execute(stmt)
        return [_to_row(m) for m in result.scalars().all()]
