"""IAnalyticsKPIQueryPort — read-only KPI snapshots from analytics BC."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class KPISnapshotDTO:
    """Port DTO — no analytics.domain imports."""

    kpi_type: str
    value: float | None
    unit: str
    trend_delta: float
    status: str


@dataclass(frozen=True, slots=True)
class AnomalySnapshotDTO:
    signal_type: str
    severity: str
    observed_value: float
    threshold: float


@dataclass(frozen=True, slots=True)
class AnalyticsKPIBundleDTO:
    kpis: tuple[KPISnapshotDTO, ...] = field(default_factory=tuple)
    anomalies: tuple[AnomalySnapshotDTO, ...] = field(default_factory=tuple)


class IAnalyticsKPIQueryPort(ABC):
    @abstractmethod
    async def load_kpi_bundle(self, tenant_id: UUID) -> AnalyticsKPIBundleDTO: ...
