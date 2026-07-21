"""Abstract ML training port — in-process default; external platforms are adapters only."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class TrainingResult:
    artifact_bytes: bytes
    accuracy_metrics: dict[str, Any]
    feature_names: list[str]
    feature_baseline: list[list[float]] = field(default_factory=list)
    passed_accuracy_gate: bool = True
    failure_reason: str | None = None


class IMLTrainingPort(ABC):
    @abstractmethod
    def train(
        self,
        *,
        algorithm: str,
        model_type: str,
        feature_names: list[str],
        features: list[list[float]],
        labels: list[float],
    ) -> TrainingResult: ...
