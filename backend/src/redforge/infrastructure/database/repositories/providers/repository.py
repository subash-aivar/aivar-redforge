"""SqlAlchemy repository for the Providers bounded context.

Receives an active AsyncSession. NEVER commits or rolls back.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyProviderRepository:
    """Async repository for Provider persistence."""

    _TABLE = "providers"

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, provider_id: str) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(f"SELECT data FROM {self._TABLE} WHERE id = :id"),
            {"id": provider_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def list_all(
        self, provider_type: str | None, enabled: bool | None,
        limit: int, offset: int,
    ) -> list[dict[str, Any]]:
        conditions: list[str] = []
        params: dict[str, Any] = {"lim": limit, "off": offset}

        if provider_type is not None:
            conditions.append("data->>'provider_type' = :ptype")
            params["ptype"] = provider_type
        if enabled is not None:
            conditions.append("data->>'enabled' = :enabled")
            params["enabled"] = str(enabled).lower()

        where = " AND ".join(conditions) if conditions else "1=1"
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

    async def update(self, provider_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        existing = await self.get_by_id(provider_id)
        if existing is None:
            return None
        existing.update(data)
        await self.save(existing)
        return existing
