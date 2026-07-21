"""ACL port — pull current asset scores from exposure BC (no domain leakage)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


class IExposureScoreQueryPort(ABC):
    @abstractmethod
    async def get_asset_scores(self, tenant_id: UUID) -> dict[str, float]: ...

    @abstractmethod
    async def get_score_input_version(self, tenant_id: UUID) -> int: ...
