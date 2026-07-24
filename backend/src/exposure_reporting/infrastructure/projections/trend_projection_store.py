"""Historical exposure trend projection store."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from exposure_reporting.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(slots=True)
class TrendPoint:
    computed_at: str
    tenant_exposure_score: float
    asset_count: int
    score_input_version: str


class ITrendProjectionStore(Protocol):
    """Structural port — satisfied by both TrendProjectionStore (in-memory)
    and PgTrendProjectionStore (postgres_projection_stores.py)."""

    async def append(
        self,
        tenant_id: TenantId,
        *,
        tenant_exposure_score: float,
        asset_count: int,
        at: datetime,
        score_input_version: str,
    ) -> None: ...
    async def list_points(self, tenant_id: TenantId) -> list[TrendPoint]: ...
    async def clear(self, tenant_id: TenantId) -> None: ...


class TrendProjectionStore:
    def __init__(self) -> None:
        self._points: dict[str, list[TrendPoint]] = {}

    async def append(
        self,
        tenant_id: TenantId,
        *,
        tenant_exposure_score: float,
        asset_count: int,
        at: datetime,
        score_input_version: str,
    ) -> None:
        self._points.setdefault(str(tenant_id), []).append(
            TrendPoint(
                computed_at=at.isoformat(),
                tenant_exposure_score=tenant_exposure_score,
                asset_count=asset_count,
                score_input_version=score_input_version,
            )
        )

    async def list_points(self, tenant_id: TenantId) -> list[TrendPoint]:
        return list(self._points.get(str(tenant_id), []))

    async def clear(self, tenant_id: TenantId) -> None:
        self._points.pop(str(tenant_id), None)
