"""ACL port — pull exposure read-model data into reporting (no domain leakage)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from exposure_reporting.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class ExposureSnapshotPoint:
    asset_ref_id: str
    composite_score: float
    computed_at: str
    score_input_version: int


@dataclass(frozen=True, slots=True)
class ExposureDataSnapshot:
    asset_scores: dict[str, float]
    amplifier_weight_prevalence: dict[str, float]
    score_input_version: int
    snapshot_history: tuple[ExposureSnapshotPoint, ...] = ()
    threat_cache_stale: bool = False
    metadata: dict[str, object] = field(default_factory=dict)


class IExposureDataQueryPort(ABC):
    @abstractmethod
    async def load_snapshot(self, tenant_id: TenantId) -> ExposureDataSnapshot: ...
