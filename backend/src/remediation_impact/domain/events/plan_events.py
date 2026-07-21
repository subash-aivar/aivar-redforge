"""Domain events for ExposureReductionPlan."""

from __future__ import annotations

from dataclasses import dataclass

from remediation_impact.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ExposureReductionPlanGenerated(BaseDomainEvent):
    projected_exposure_reduction: float = 0.0
    algorithm: str = ""
    step_count: int = 0


@dataclass(frozen=True, slots=True)
class ExposureReductionPlanCommitted(BaseDomainEvent):
    committed_by: str = ""
