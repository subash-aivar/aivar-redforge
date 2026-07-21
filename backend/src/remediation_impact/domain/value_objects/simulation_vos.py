"""Simulation value objects (Finalization D5)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class RemediationCandidate:
    remediation_id: str
    affected_asset_refs: tuple[str, ...]
    estimated_amplifier_removals: tuple[str, ...] = ()
    estimated_base_reduction: float = 0.0  # absolute score reduction if alone


@dataclass(frozen=True, slots=True)
class PlanStep:
    remediation_id: str
    marginal_delta: float
    affected_asset_refs: tuple[str, ...]
    rank: int


@dataclass(frozen=True, slots=True)
class SimulationResult:
    plan_steps: tuple[PlanStep, ...]
    projected_exposure_reduction: float
    algorithm: str
    top_k: int
    sample_size: int
    approximation_mode: str
    simulation_seed: int
    score_input_version: int
    estimated_business_impact: float = 0.0
    total_assets: int = 0
    metadata: dict[str, object] = field(default_factory=dict)
