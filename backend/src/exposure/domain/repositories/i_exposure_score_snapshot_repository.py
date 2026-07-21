from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from exposure.domain.aggregates.exposure_score_snapshot import ExposureScoreSnapshot
    from exposure.domain.value_objects.identifiers import TenantId


class IExposureScoreSnapshotRepository(ABC):
    @abstractmethod
    async def save(self, tenant_id: TenantId, snapshot: ExposureScoreSnapshot) -> None: ...

    @abstractmethod
    async def find_latest_by_asset(
        self, tenant_id: TenantId, asset_ref_id: UUID
    ) -> ExposureScoreSnapshot | None: ...

    @abstractmethod
    async def exists_after(
        self, tenant_id: TenantId, asset_ref_id: UUID, after: datetime
    ) -> bool: ...
