"""SqlAlchemy repository for the Policies bounded context.

Receives an active AsyncSession. NEVER commits or rolls back.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyPolicyRepository:
    """Async repository for ValidationPolicy persistence."""

    _TABLE = "validation_policies"

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, policy_id: str) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(f"SELECT data FROM {self._TABLE} WHERE id = :id"),
            {"id": policy_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def get_by_id_for_organization(
        self, policy_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(
                f"SELECT data FROM {self._TABLE} "
                f"WHERE id = :id AND data->>'organization_id' = :org_id"
            ),
            {"id": policy_id, "org_id": organization_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def list_by_organization(
        self, org_id: str, enabled: bool | None, limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        conditions = ["data->>'organization_id' = :org_id"]
        params: dict[str, Any] = {"org_id": org_id, "lim": limit, "off": offset}

        if enabled is not None:
            conditions.append("data->>'enabled' = :enabled")
            params["enabled"] = str(enabled).lower()

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

    async def update(self, policy_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = await self.get_by_id(policy_id)
        if existing is None:
            return None
        existing.update(data)
        await self.save(existing)
        return existing

    async def update_for_organization(
        self, policy_id: str, organization_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        existing = await self.get_by_id_for_organization(policy_id, organization_id)
        if existing is None:
            return None
        existing.update(data)
        await self.save(existing)
        return existing

    async def delete(self, policy_id: str) -> None:
        await self._session.execute(
            text(f"DELETE FROM {self._TABLE} WHERE id = :id"),
            {"id": policy_id},
        )

    async def delete_for_organization(
        self, policy_id: str, organization_id: str
    ) -> bool:
        existing = await self.get_by_id_for_organization(policy_id, organization_id)
        if existing is None:
            return False
        await self.delete(policy_id)
        return True
