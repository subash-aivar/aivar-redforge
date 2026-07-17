"""Domain unit tests for Attack Path Engine — M22 Phase 5."""

from __future__ import annotations

import pytest

from redforge.domain.attack_path.entity import AttackPath
from redforge.domain.attack_path.exceptions import (
    AttackPathSeedInvalidError,
    InferenceGateRejectedError,
    InvalidPathStatusTransitionError,
)
from redforge.domain.attack_path.graph import (
    GraphEdge,
    GraphNode,
    build_graph_from_fusion,
    discover_paths,
)
from redforge.domain.attack_path.policies import InferenceGatePolicy, PathExplosionPolicy
from redforge.domain.attack_path.value_objects import (
    AttackStep,
    PathConfidence,
    PathExplosionBudget,
    PathStatus,
    StepType,
    exposure_score_for,
    propagate_confidence,
    propagate_risk,
    weakest_path_confidence,
)
from redforge.domain.threat_intel.fusion_value_objects import (
    FusedIndicatorType,
    FusionConfidence,
)


def _node(
    entity_id: str,
    key: str,
    *,
    confidence: FusionConfidence = FusionConfidence.HIGH,
    technique_id: str | None = None,
) -> GraphNode:
    return GraphNode(
        entity_id=entity_id,
        canonical_key=key,
        indicator_type=FusedIndicatorType.TECHNIQUE,
        display_name=key,
        confidence=confidence,
        technique_id=technique_id or key.split(":")[-1],
        kill_chain_phase="initial-access",
        evidence_refs=(entity_id,),
    )


class TestPathConfidence:
    def test_weakest_link(self) -> None:
        assert (
            weakest_path_confidence(
                [PathConfidence.HIGH, PathConfidence.LOW, PathConfidence.MEDIUM]
            )
            is PathConfidence.LOW
        )

    def test_propagate_confidence_and_risk(self) -> None:
        assert (
            propagate_confidence(PathConfidence.HIGH, PathConfidence.MEDIUM)
            is PathConfidence.MEDIUM
        )
        assert propagate_risk(0.4, 0.8) == 0.8

    def test_exposure_score_kev_boost(self) -> None:
        score = exposure_score_for(FusionConfidence.MEDIUM, is_kev=True)
        assert score > exposure_score_for(FusionConfidence.MEDIUM)


class TestInferenceGate:
    def test_rejects_without_observed_predecessor(self) -> None:
        gate = InferenceGatePolicy()
        with pytest.raises(InferenceGateRejectedError):
            gate.may_infer(previous_step=None, proposed_confidence=PathConfidence.MEDIUM)

    def test_requires_sequence_adjacent_observed(self) -> None:
        gate = InferenceGatePolicy()
        prev = AttackStep(
            sequence=0,
            entity_id="a",
            canonical_key="technique:T0001",
            step_type=StepType.INFERRED,
            confidence=PathConfidence.HIGH,
            technique_id="T0001",
            evidence_refs=(),
            relationship_type=None,
            kill_chain_phase=None,
            observed_at=None,
            inferred_from_step=None,
            exposure_score=0.5,
        )
        with pytest.raises(InferenceGateRejectedError):
            gate.may_infer(previous_step=prev, proposed_confidence=PathConfidence.MEDIUM)


class TestGraphTraversal:
    def test_bfs_discovers_observed_path_and_handles_cycle(self) -> None:
        a = _node("id-a", "technique:T0001", technique_id="T0001")
        b = _node("id-b", "technique:T0002", technique_id="T0002")
        c = _node("id-c", "technique:T0003", technique_id="T0003")
        graph = build_graph_from_fusion(
            nodes=[a, b, c],
            edges=[
                GraphEdge("id-a", "id-b", "precedes", FusionConfidence.HIGH, "e1", True),
                GraphEdge("id-b", "id-c", "precedes", FusionConfidence.MEDIUM, "e2", True),
                GraphEdge("id-c", "id-a", "precedes", FusionConfidence.LOW, "e3", True),
            ],
        )
        paths = discover_paths(
            graph,
            seed_entity_id="id-a",
            explosion=PathExplosionPolicy(PathExplosionBudget(max_depth=4, max_fan_out=4)),
        )
        assert paths
        assert paths[0].steps[0].entity_id == "id-a"
        # Cycle back to seed must not infinite-loop; path terminates.
        assert all(len(p.steps) <= 5 for p in paths)

    def test_inferred_edge_gated(self) -> None:
        a = _node("id-a", "technique:T0001", confidence=FusionConfidence.HIGH)
        b = _node("id-b", "technique:T0002", confidence=FusionConfidence.MEDIUM)
        graph = build_graph_from_fusion(
            nodes=[a, b],
            edges=[
                GraphEdge("id-a", "id-b", "used-by", FusionConfidence.LOW, "e1", False),
            ],
        )
        paths = discover_paths(graph, seed_entity_id="id-a")
        # Inferred hop allowed because seed is OBSERVED HIGH ≥ MEDIUM.
        assert any(len(p.steps) >= 2 for p in paths)

    def test_missing_seed_raises(self) -> None:
        graph = build_graph_from_fusion(nodes=[], edges=[])
        with pytest.raises(AttackPathSeedInvalidError):
            discover_paths(graph, seed_entity_id="missing")


class TestPathStatusMachine:
    def test_active_to_contained_to_historical(self) -> None:
        path = AttackPath.create_computed(
            id="01TESTPATH0000000000000001",
            organization_id="01TESTORG0000000000000001",
            root_entity_id="seed",
            root_canonical_key="technique:T0001",
            terminal_entity_id="seed",
            path_confidence=PathConfidence.MEDIUM,
            technique_coverage=["T0001"],
            attributed_actors=[],
            step_count=1,
            evidence_count=1,
            max_exposure_score=0.5,
            first_step_at=None,
            last_step_at=None,
        )
        assert path.status is PathStatus.ACTIVE
        path.contain()
        assert path.status is PathStatus.CONTAINED
        path.archive()
        assert path.status is PathStatus.HISTORICAL
        with pytest.raises(InvalidPathStatusTransitionError):
            path.contain()
