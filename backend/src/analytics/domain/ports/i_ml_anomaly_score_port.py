"""ACL port — score an observation via deployed Isolation Forest (Phase 5)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from analytics.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class MLAnomalyScoreResult:
    available: bool
    anomaly_score: float
    is_anomaly: bool
    reason: str = ""


class IMLAnomalyScorePort(ABC):
    @abstractmethod
    async def score(
        self, tenant_id: TenantId, *, features: list[float]
    ) -> MLAnomalyScoreResult: ...
