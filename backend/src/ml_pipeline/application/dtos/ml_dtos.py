from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class MLModelDTO:
    model_id: str
    tenant_id: str
    model_type: str
    algorithm: str
    status: str
    dataset_id: str
    accuracy_metrics: dict[str, Any] = field(default_factory=dict)
    artifact_ref: str | None = None
    artifact_hash: str | None = None
    failure_reason: str | None = None
    deployed_by: str | None = None
    last_psi_score: float | None = None


@dataclass(frozen=True, slots=True)
class PredictiveRiskSignalDTO:
    signal_id: str
    model_id: str
    asset_ref_id: str
    signal_type: str
    score: float
    confidence: float
    created_at: str
    expires_at: str
    active: bool


@dataclass(frozen=True, slots=True)
class GovernanceRecordDTO:
    model_id: str
    action: str
    actor: str
    from_status: str
    to_status: str
    occurred_at: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class ColdStartResponseDTO:
    status: str
    available_from: str | None = None
    cold_start_reason: str | None = None
