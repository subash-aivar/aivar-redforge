"""Entities for cloud risk correlation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast
from uuid import uuid4

from redforge.domain.cloud_security.risk.value_objects import (
    RiskCategory,
    RiskSource,
    _as_float,
)


@dataclass(frozen=True, slots=True)
class RiskEvidence:
    evidence_id: str
    source: RiskSource
    summary: str
    details: dict[str, Any]
    observed_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source.value,
            "summary": self.summary,
            "details": dict(self.details),
            "observed_at": self.observed_at.isoformat() if self.observed_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RiskEvidence:
        observed = data.get("observed_at")
        observed_at = None
        if isinstance(observed, str) and observed:
            observed_at = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        src = data.get("source", "COMPOSITE")
        raw_details = data.get("details")
        details: dict[str, Any] = (
            cast("dict[str, Any]", dict(raw_details))
            if isinstance(raw_details, dict)
            else {}
        )
        return cls(
            evidence_id=str(data.get("evidence_id") or uuid4()),
            source=RiskSource(str(src).upper()),
            summary=str(data.get("summary", "")),
            details=details,
            observed_at=observed_at,
        )


@dataclass(frozen=True, slots=True)
class RiskContribution:
    """Per-dimension contribution with weight applied."""

    dimension: str
    raw_score: float
    weight: float
    weighted_score: float
    rationale: str
    category: RiskCategory = RiskCategory.COMPOSITE

    def to_dict(self) -> dict[str, object]:
        return {
            "dimension": self.dimension,
            "raw_score": self.raw_score,
            "weight": self.weight,
            "weighted_score": self.weighted_score,
            "rationale": self.rationale,
            "category": self.category.value,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RiskContribution:
        cat = data.get("category", "COMPOSITE")
        return cls(
            dimension=str(data.get("dimension", "")),
            raw_score=_as_float(data.get("raw_score"), 0.0),
            weight=_as_float(data.get("weight"), 0.0),
            weighted_score=_as_float(data.get("weighted_score"), 0.0),
            rationale=str(data.get("rationale", "")),
            category=RiskCategory(str(cat).upper()),
        )


# Freeze alias
RiskScoreComponent = RiskContribution


@dataclass(frozen=True, slots=True)
class RiskHistoryEntry:
    history_id: str
    overall_score: float
    state: str
    calculation_version: str
    recorded_at: datetime
    reason: str = ""
    dimensions: dict[str, float] | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "history_id": self.history_id,
            "overall_score": self.overall_score,
            "state": self.state,
            "calculation_version": self.calculation_version,
            "recorded_at": self.recorded_at.isoformat(),
            "reason": self.reason,
            "dimensions": dict(self.dimensions or {}),
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> RiskHistoryEntry:
        recorded = data.get("recorded_at")
        if isinstance(recorded, str):
            recorded_at = datetime.fromisoformat(recorded.replace("Z", "+00:00"))
        elif isinstance(recorded, datetime):
            recorded_at = recorded
        else:
            raise ValueError("recorded_at required")
        dims = data.get("dimensions") or {}
        dim_map: dict[str, float] = {}
        if isinstance(dims, dict):
            dim_map = {str(k): _as_float(v, 0.0) for k, v in dims.items()}
        return cls(
            history_id=str(data.get("history_id") or uuid4()),
            overall_score=_as_float(data.get("overall_score"), 0.0),
            state=str(data.get("state", "ACTIVE")),
            calculation_version=str(data.get("calculation_version", "")),
            recorded_at=recorded_at,
            reason=str(data.get("reason", "")),
            dimensions=dim_map,
        )


@dataclass(frozen=True, slots=True)
class RiskWeight:
    profile_name: str
    weights: dict[str, float]
    provider_type: str = "*"

    def to_dict(self) -> dict[str, object]:
        return {
            "profile_name": self.profile_name,
            "weights": dict(self.weights),
            "provider_type": self.provider_type,
        }


@dataclass(frozen=True, slots=True)
class RiskException:
    exception_id: str
    reason: str
    approved_by: str
    expires_at: datetime | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "exception_id": self.exception_id,
            "reason": self.reason,
            "approved_by": self.approved_by,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
