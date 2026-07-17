"""Attack Path policies — M22 Phase 5.

`InferenceGatePolicy`: an INFERRED step is allowed only when the
immediately preceding step in sequence (sequence ±1 adjacency —
Hardening Review P2) is OBSERVED and confidence ≥ MEDIUM.

`PathExplosionPolicy`: enforces `PathExplosionBudget` caps during BFS.
"""

from __future__ import annotations

from typing import TypeVar

from redforge.domain.attack_path.exceptions import InferenceGateRejectedError
from redforge.domain.attack_path.value_objects import (
    AttackStep,
    PathConfidence,
    PathExplosionBudget,
    StepType,
    path_confidence_rank,
)

_T = TypeVar("_T")

_MIN_GATE_CONFIDENCE = PathConfidence.MEDIUM


class InferenceGatePolicy:
    """Gate inferred hops on sequence-adjacent observed evidence."""

    def may_infer(
        self,
        *,
        previous_step: AttackStep | None,
        proposed_confidence: PathConfidence,
    ) -> None:
        if previous_step is None:
            raise InferenceGateRejectedError(
                "INFERRED step requires a preceding OBSERVED step (sequence adjacency)"
            )
        if previous_step.step_type is not StepType.OBSERVED:
            raise InferenceGateRejectedError(
                "INFERRED step requires the immediately preceding step "
                f"(sequence {previous_step.sequence}) to be OBSERVED"
            )
        if path_confidence_rank(previous_step.confidence) < path_confidence_rank(
            _MIN_GATE_CONFIDENCE
        ):
            raise InferenceGateRejectedError(
                "INFERRED step requires preceding OBSERVED confidence ≥ MEDIUM"
            )
        if path_confidence_rank(proposed_confidence) < path_confidence_rank(
            PathConfidence.LOW
        ):
            raise InferenceGateRejectedError("proposed inferred confidence is invalid")


class PathExplosionPolicy:
    """Caps BFS expansion to prevent resource exhaustion."""

    def __init__(self, budget: PathExplosionBudget | None = None) -> None:
        self.budget = budget or PathExplosionBudget()

    def allow_depth(self, depth: int) -> bool:
        return depth <= self.budget.max_depth

    def trim_fan_out(self, edges: list[_T]) -> list[_T]:
        return edges[: self.budget.max_fan_out]

    def allow_visit(self, nodes_visited: int) -> bool:
        return nodes_visited < self.budget.max_nodes_visited

    def allow_path(self, paths_found: int) -> bool:
        return paths_found < self.budget.max_paths
