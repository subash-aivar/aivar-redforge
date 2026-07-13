"""SqlAlchemy repository for the Validation bounded context.

Receives an active AsyncSession. NEVER commits or rolls back.
Transaction lifecycle is owned by UnitOfWork.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyValidationRepository:
    """Async repository for ValidationRun persistence.

    Operates on a shared session provided by UnitOfWork.
    """

    _TABLE = "validation_runs"

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, run_id: str) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(f"SELECT data FROM {self._TABLE} WHERE id = :id"),
            {"id": run_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def get_by_id_for_organization(
        self, run_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(
                f"SELECT data FROM {self._TABLE} "
                f"WHERE id = :id AND data->>'organization_id' = :org_id"
            ),
            {"id": run_id, "org_id": organization_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def list_by_organization(
        self, org_id: str, target_id: str | None, status: str | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        conditions = ["data->>'organization_id' = :org_id"]
        params: dict[str, Any] = {"org_id": org_id, "lim": limit, "off": offset}

        if target_id is not None:
            conditions.append("data->>'target_id' = :target_id")
            params["target_id"] = target_id
        if status is not None:
            conditions.append("data->>'status' = :status")
            params["status"] = status

        where = " AND ".join(conditions)
        result = await self._session.execute(
            text(
                f"SELECT data FROM {self._TABLE} "
                f"WHERE {where} "
                f"ORDER BY data->>'created_at' DESC "
                f"LIMIT :lim OFFSET :off"
            ),
            params,
        )
        return [
            json.loads(r[0]) if isinstance(r[0], str) else dict(r[0])
            for r in result.all()
        ]

    async def save(self, data: dict[str, Any]) -> None:
        await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} (id, data) "
                f"VALUES (:id, :data) "
                f"ON CONFLICT (id) DO UPDATE SET data = :data"
            ),
            {"id": data["id"], "data": json.dumps(data)},
        )
