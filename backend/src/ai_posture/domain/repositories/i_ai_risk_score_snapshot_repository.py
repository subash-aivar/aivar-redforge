"""IAIRiskScoreSnapshotRepository."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import timedelta

    from ai_posture.domain.aggregates.ai_risk_score_snapshot import AIRiskScoreSnapshot
    from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId


class IAIRiskScoreSnapshotRepository(ABC):
    @abstractmethod
    async def save(self, snapshot: AIRiskScoreSnapshot) -> None: ...

    @abstractmethod
    async def find_latest_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId
    ) -> AIRiskScoreSnapshot | None: ...

    @abstractmethod
    async def find_history_by_asset(
        self, asset_id: AISystemAssetId, tenant_id: TenantId, limit: int
    ) -> list[AIRiskScoreSnapshot]: ...

    @abstractmethod
    async def find_stale_asset_ids(
        self, staleness_bound: timedelta, tenant_id: TenantId
    ) -> list[AISystemAssetId]: ...
