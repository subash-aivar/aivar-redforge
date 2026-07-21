from __future__ import annotations

from dataclasses import dataclass, field

from ml_pipeline.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class MLModelTrainingStarted(BaseDomainEvent):
    model_type: str = ""
    algorithm: str = ""


@dataclass(frozen=True, slots=True)
class MLModelTrained(BaseDomainEvent):
    artifact_ref: str = ""
    accuracy_metrics: dict[str, float] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class MLModelTrainingFailed(BaseDomainEvent):
    error_reason: str = ""


@dataclass(frozen=True, slots=True)
class MLModelDeployed(BaseDomainEvent):
    deployed_by: str = ""


@dataclass(frozen=True, slots=True)
class MLModelDriftDetected(BaseDomainEvent):
    psi_score: float = 0.0
    threshold: float = 0.20
    auto_deprecated: bool = False


@dataclass(frozen=True, slots=True)
class MLModelDeprecated(BaseDomainEvent):
    deprecated_by: str = ""


@dataclass(frozen=True, slots=True)
class PredictiveRiskSignalsGenerated(BaseDomainEvent):
    asset_count: int = 0
    signal_type: str = ""
