"""Value objects for the Attack Path Engine — M22 Phase 5.

`PathConfidence` is a dedicated type (Hardening Review P2) even though
its levels match fusion's four-level ladder — path calibration must not
silently track fusion or M21 investigation confidence changes.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime
from enum import StrEnum, unique

from redforge.domain.attack_path.exceptions import (
    InvalidPathConfidenceError,
    PathExplosionExceededError,
)
from redforge.domain.threat_intel.fusion_value_objects import (
    FusionConfidence,
    fusion_confidence_rank,
    min_fusion_confidence,
)


@unique
class PathStatus(StrEnum):
    """Attack-path lifecycle (Hardening Review P1: explicit state machine).

    Transitions:
      ACTIVE → CONTAINED  (operator marks path contained)
      ACTIVE → HISTORICAL (idle TTL / superseded by a newer compute)
      CONTAINED → HISTORICAL
      HISTORICAL is terminal.
    """

    ACTIVE = "active"
    CONTAINED = "contained"
    HISTORICAL = "historical"


@unique
class StepType(StrEnum):
    OBSERVED = "observed"
    INFERRED = "inferred"


@unique
class PathConfidence(StrEnum):
    """Path-level confidence — weakest link of step confidences."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


_PATH_CONFIDENCE_ORDER: dict[PathConfidence, int] = {
    PathConfidence.LOW: 0,
    PathConfidence.MEDIUM: 1,
    PathConfidence.HIGH: 2,
    PathConfidence.VERY_HIGH: 3,
}


def path_confidence_from_fusion(level: FusionConfidence) -> PathConfidence:
    try:
        return PathConfidence(level.value)
    except ValueError as exc:
        raise InvalidPathConfidenceError(level.value) from exc


def weakest_path_confidence(levels: list[PathConfidence]) -> PathConfidence:
    if not levels:
        raise InvalidPathConfidenceError("empty confidence list")
    weakest = levels[0]
    for level in levels[1:]:
        if _PATH_CONFIDENCE_ORDER[level] < _PATH_CONFIDENCE_ORDER[weakest]:
            weakest = level
    return weakest


def path_confidence_rank(level: PathConfidence) -> int:
    return _PATH_CONFIDENCE_ORDER[level]


@dataclass(frozen=True, slots=True)
class AttackStep:
    """One hop in an attack path — value object, not an aggregate.

    Stored via `AttackPathStepRepository`; the `AttackPath` aggregate
    root holds only summary counts (Hardening Review P0).
    """

    sequence: int
    entity_id: str
    canonical_key: str
    step_type: StepType
    confidence: PathConfidence
    technique_id: str | None
    evidence_refs: tuple[str, ...]
    relationship_type: str | None
    kill_chain_phase: str | None
    observed_at: datetime | None
    inferred_from_step: int | None
    exposure_score: float


@dataclass(frozen=True, slots=True)
class KillChainMapping:
    """Ordered ATT&CK tactic shortnames for kill-chain presentation."""

    phases: tuple[str, ...]

    @staticmethod
    def enterprise_default() -> KillChainMapping:
        return KillChainMapping(
            phases=(
                "reconnaissance",
                "resource-development",
                "initial-access",
                "execution",
                "persistence",
                "privilege-escalation",
                "defense-evasion",
                "credential-access",
                "discovery",
                "lateral-movement",
                "collection",
                "command-and-control",
                "exfiltration",
                "impact",
            )
        )

    def index_of(self, phase: str) -> int | None:
        try:
            return self.phases.index(phase)
        except ValueError:
            return None


@dataclass(frozen=True, slots=True)
class PathExplosionBudget:
    """Hard caps for graph traversal (defense-in-depth against path explosion).

    Caps are intentionally more conservative than the architecture
    freeze's aspirational depth=12/fan-out=8 (Hardening Review P0:
    8^12 is not operable against PostgreSQL at tenant scale). Validated
    against bounded in-memory ATT&CK graphs in unit tests.
    """

    max_depth: int = 6
    max_fan_out: int = 4
    max_paths: int = 32
    max_nodes_visited: int = 256

    def __post_init__(self) -> None:
        if self.max_depth < 1 or self.max_depth > 12:
            raise PathExplosionExceededError(
                f"max_depth must be in [1, 12], got {self.max_depth}"
            )
        if self.max_fan_out < 1 or self.max_fan_out > 8:
            raise PathExplosionExceededError(
                f"max_fan_out must be in [1, 8], got {self.max_fan_out}"
            )
        if self.max_paths < 1:
            raise PathExplosionExceededError("max_paths must be >= 1")
        if self.max_nodes_visited < 1:
            raise PathExplosionExceededError("max_nodes_visited must be >= 1")


def exposure_score_for(
    confidence: FusionConfidence | PathConfidence,
    *,
    is_kev: bool = False,
    epss_probability: float | None = None,
) -> float:
    """Deterministic exposure score in [0.0, 1.0] from fused risk signals.

    Never fabricated from empty evidence: callers must only invoke this
    for OBSERVED nodes that carry real fusion/reference metadata.
    """
    if isinstance(confidence, FusionConfidence):
        rank = fusion_confidence_rank(confidence)
        base = (rank + 1) / 4.0
    else:
        rank = path_confidence_rank(confidence)
        base = (rank + 1) / 4.0
    score = base
    if is_kev:
        score = min(1.0, score + 0.25)
    if epss_probability is not None:
        score = min(1.0, max(score, epss_probability))
    return round(score, 4)


def propagate_confidence(
    previous: PathConfidence, edge_confidence: PathConfidence
) -> PathConfidence:
    """Confidence propagation along a path — weakest-link semantics."""
    # Reuse fusion min helper via value mapping
    prev_f = FusionConfidence(previous.value)
    edge_f = FusionConfidence(edge_confidence.value)
    return PathConfidence(min_fusion_confidence(prev_f, edge_f).value)


def propagate_risk(previous: float, hop_exposure: float) -> float:
    """Risk propagation: path risk is the max hop exposure seen so far
    (worst-link exposure), never an invented average."""
    return max(previous, hop_exposure)
