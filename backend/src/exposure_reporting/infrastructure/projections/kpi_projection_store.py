"""KPI projection store (read model)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


class IKpiProjectionStore(Protocol):
    """Structural port — satisfied by both KpiProjectionStore (in-memory)
    and PgKpiProjectionStore (postgres_projection_stores.py)."""

    async def upsert(self, tenant_id: UUID, kpi: dict[str, Any], at: datetime) -> None: ...
    async def get(self, tenant_id: UUID) -> dict[str, Any] | None: ...
    async def clear(self, tenant_id: UUID) -> None: ...


class KpiProjectionStore:
    def __init__(self) -> None:
        self._rows: dict[str, dict[str, Any]] = {}

    async def upsert(self, tenant_id: UUID, kpi: dict[str, Any], at: datetime) -> None:
        self._rows[str(tenant_id)] = {**kpi, "updated_at": at.isoformat()}

    async def get(self, tenant_id: UUID) -> dict[str, Any] | None:
        return self._rows.get(str(tenant_id))

    async def clear(self, tenant_id: UUID) -> None:
        self._rows.pop(str(tenant_id), None)
