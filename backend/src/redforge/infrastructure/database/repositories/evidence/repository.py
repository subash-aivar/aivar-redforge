"""SqlAlchemy repository for the Evidence bounded context.

Receives an active AsyncSession. NEVER commits or rolls back.
Uses window function for efficient count+data in one query.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SqlAlchemyEvidenceRepository:
    """Async repository for Evidence persistence (read-heavy, append-only)."""

    _TABLE = "evidence"

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_id(self, evidence_id: str) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(f"SELECT data FROM {self._TABLE} WHERE id = :id"),
            {"id": evidence_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def get_by_id_for_organization(
        self, evidence_id: str, organization_id: str
    ) -> dict[str, Any] | None:
        result = await self._session.execute(
            text(
                f"SELECT data FROM {self._TABLE} "
                f"WHERE id = :id AND data->>'organization_id' = :org_id"
            ),
            {"id": evidence_id, "org_id": organization_id},
        )
        row = result.first()
        if row is None:
            return None
        return json.loads(row[0]) if isinstance(row[0], str) else dict(row[0])

    async def list_by_run(
        self, run_id: str, target_id: str | None, result_filter: str | None,
        limit: int, offset: int,
    ) -> tuple[list[dict[str, Any]], int]:
        """Returns (items, total) in a single query via window function."""
        conditions = ["data->>'run_id' = :run_id"]
        params: dict[str, Any] = {"run_id": run_id, "lim": limit, "off": offset}

        if target_id is not None:
            conditions.append("data->>'target_id' = :target_id")
            params["target_id"] = target_id
        if result_filter is not None:
            conditions.append("data->>'result' = :result")
            params["result"] = result_filter

        where = " AND ".join(conditions)
        result = await self._session.execute(
            text(
                f"SELECT data, COUNT(*) OVER() AS total "
                f"FROM {self._TABLE} "
                f"WHERE {where} "
                f"ORDER BY data->>'created_at' DESC "
                f"LIMIT :lim OFFSET :off"
            ),
            params,
        )
        rows = result.all()
        if not rows:
            return [], 0
        total = rows[0][1]
        items = [
            json.loads(r[0]) if isinstance(r[0], str) else dict(r[0])
            for r in rows
        ]
        return items, total

    async def save(self, data: dict[str, Any]) -> None:
        """Append-only upsert. Evidence is never deleted — only created."""
        await self._session.execute(
            text(
                f"INSERT INTO {self._TABLE} (id, data) VALUES (:id, :data) "
                f"ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data"
            ),
            {"id": data["id"], "data": json.dumps(data)},
        )
