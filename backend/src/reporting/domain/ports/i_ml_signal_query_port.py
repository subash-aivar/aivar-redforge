"""IMLSignalQueryPort — read predictive signals for Predictive Threat Forecast."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class MLSignalDTO:
    signal_type: str
    asset_ref_id: str
    score: float
    technique_id: str = ""
    exploitation_probability: float | None = None


@dataclass(frozen=True, slots=True)
class MLSignalBundleDTO:
    signals: tuple[MLSignalDTO, ...] = field(default_factory=tuple)
    model_deployed: bool = False


class IMLSignalQueryPort(ABC):
    @abstractmethod
    async def load_active_signals(self, tenant_id: UUID) -> MLSignalBundleDTO: ...
