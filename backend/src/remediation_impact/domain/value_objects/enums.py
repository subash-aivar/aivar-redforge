"""Enums for remediation_impact BC (M32 Phase 4)."""

from __future__ import annotations

from enum import StrEnum


class PlanStatus(StrEnum):
    GENERATED = "Generated"
    COMMITTED = "Committed"


class SimulationAlgorithm(StrEnum):
    GREEDY_MARGINAL_CONTRIBUTION = "GreedyMarginalContribution"


class ApproximationMode(StrEnum):
    EXACT = "Exact"
    SAMPLED = "Sampled"


class RemediationImpactRole(StrEnum):
    VIEWER = "exposure:viewer"
    ANALYST = "exposure:analyst"
    SIMULATION_READER = "exposure:simulation_reader"
    ENGINEER = "exposure:engineer"
    ADMIN = "exposure:admin"
