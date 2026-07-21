"""ACL port — score an observation via deployed Isolation Forest (Phase 5)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class MLAnomalyScoreResult:
    available: bool
    anomaly_score: float
    is_anomaly: bool
    reason: str = ""


class IMLAnomalyScorePort(ABC):
    @abstractmethod
    async def score(self, tenant_id: UUID, *, features: list[float]) -> MLAnomalyScoreResult: ...
