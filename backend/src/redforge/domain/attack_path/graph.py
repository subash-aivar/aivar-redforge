"""ATT&CK / fusion attack-graph construction and BFS path discovery.

Pure domain module: no I/O. The application layer builds an
`AttackGraph` from fused indicators + fused relationships, then asks
`discover_paths` for evidence-backed paths under policy caps.

Cycle handling: each BFS branch tracks the set of visited entity IDs;
revisiting a node on the same branch is rejected (no infinite loops).
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from redforge.domain.attack_path.exceptions import (
    AttackPathComputeBudgetExceededError,
    AttackPathSeedInvalidError,
    InferenceGateRejectedError,
)
from redforge.domain.attack_path.policies import InferenceGatePolicy, PathExplosionPolicy
from redforge.domain.attack_path.value_objects import (
    AttackStep,
    KillChainMapping,
    PathConfidence,
    PathExplosionBudget,
    StepType,
    exposure_score_for,
    path_confidence_from_fusion,
    propagate_confidence,
    propagate_risk,
    weakest_path_confidence,
)

if TYPE_CHECKING:
    from redforge.domain.threat_intel.fusion_value_objects import (
        FusedIndicatorType,
        FusionConfidence,
    )


@dataclass(frozen=True, slots=True)
class GraphNode:
    entity_id: str
    canonical_key: str
    indicator_type: FusedIndicatorType
    display_name: str
    confidence: FusionConfidence
    technique_id: str | None
    kill_chain_phase: str | None
    is_kev: bool = False
    epss_probability: float | None = None
    evidence_refs: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source_entity_id: str
    target_entity_id: str
    relationship_type: str
    confidence: FusionConfidence
    evidence_ref: str | None
    #: Edges that come directly from fused/reference data are OBSERVED;
    #: edges synthesized solely from ATT&CK `precedes` without a fused
    #: relationship row are INFERRED candidates.
    observed: bool


@dataclass(slots=True)
class AttackGraph:
    """Directed multigraph of fused intelligence nodes."""

    nodes: dict[str, GraphNode] = field(default_factory=dict)
    # adjacency: source_id → list[GraphEdge]
    outbound: dict[str, list[GraphEdge]] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes[node.entity_id] = node

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_entity_id not in self.nodes or edge.target_entity_id not in self.nodes:
            return
        self.outbound.setdefault(edge.source_entity_id, []).append(edge)

    def get(self, entity_id: str) -> GraphNode | None:
        return self.nodes.get(entity_id)


@dataclass(frozen=True, slots=True)
class DiscoveredPath:
    steps: tuple[AttackStep, ...]
    path_confidence: PathConfidence
    max_exposure_score: float
    technique_coverage: tuple[str, ...]
    attributed_actors: tuple[str, ...]


def discover_paths(
    graph: AttackGraph,
    *,
    seed_entity_id: str,
    explosion: PathExplosionPolicy | None = None,
    inference_gate: InferenceGatePolicy | None = None,
    kill_chain: KillChainMapping | None = None,
) -> list[DiscoveredPath]:
    """BFS path discovery from a fused-indicator seed.

    Seed step is always OBSERVED (the seed itself is fusion evidence).
    Subsequent hops:
      - OBSERVED if the edge is observed in fusion relationships
      - INFERRED only when `InferenceGatePolicy` permits (adjacent
        OBSERVED + confidence ≥ MEDIUM)
    """
    policy = explosion or PathExplosionPolicy(PathExplosionBudget())
    gate = inference_gate or InferenceGatePolicy()
    chain = kill_chain or KillChainMapping.enterprise_default()

    seed = graph.get(seed_entity_id)
    if seed is None:
        raise AttackPathSeedInvalidError(
            f"Seed entity {seed_entity_id!r} is not present in the attack graph"
        )
    if seed.confidence is None:
        raise AttackPathSeedInvalidError(
            f"Seed entity {seed_entity_id!r} has no fusion confidence"
        )

    seed_step = _node_to_step(
        seed,
        sequence=0,
        step_type=StepType.OBSERVED,
        confidence=path_confidence_from_fusion(seed.confidence),
        relationship_type=None,
        inferred_from_step=None,
        kill_chain=chain,
    )

    # Queue items: (current_entity_id, steps_so_far, visited_ids, depth, risk)
    queue: deque[
        tuple[str, list[AttackStep], frozenset[str], int, float]
    ] = deque()
    queue.append(
        (
            seed_entity_id,
            [seed_step],
            frozenset({seed_entity_id}),
            0,
            seed_step.exposure_score,
        )
    )

    found: list[DiscoveredPath] = []
    nodes_visited = 0

    while queue:
        if not policy.allow_path(len(found)):
            break
        entity_id, steps, visited, depth, risk = queue.popleft()
        nodes_visited += 1
        if not policy.allow_visit(nodes_visited):
            raise AttackPathComputeBudgetExceededError(
                f"max_nodes_visited={policy.budget.max_nodes_visited}"
            )

        edges = list(graph.outbound.get(entity_id, []))
        # Prefer observed edges, then by relationship type for determinism.
        edges.sort(key=lambda e: (not e.observed, e.relationship_type, e.target_entity_id))
        edges = policy.trim_fan_out(edges)

        expanded = False
        for edge in edges:
            assert isinstance(edge, GraphEdge)
            if edge.target_entity_id in visited:
                continue  # cycle on this branch
            next_depth = depth + 1
            if not policy.allow_depth(next_depth):
                continue
            target = graph.get(edge.target_entity_id)
            if target is None:
                continue

            edge_conf = path_confidence_from_fusion(edge.confidence)
            prev = steps[-1]
            step_conf = propagate_confidence(prev.confidence, edge_conf)

            if edge.observed:
                step_type = StepType.OBSERVED
                inferred_from: int | None = None
            else:
                step_type = StepType.INFERRED
                try:
                    gate.may_infer(previous_step=prev, proposed_confidence=step_conf)
                except InferenceGateRejectedError:
                    continue
                inferred_from = prev.sequence

            next_step = _node_to_step(
                target,
                sequence=prev.sequence + 1,
                step_type=step_type,
                confidence=step_conf,
                relationship_type=edge.relationship_type,
                inferred_from_step=inferred_from,
                kill_chain=chain,
                extra_evidence=(edge.evidence_ref,) if edge.evidence_ref else (),
            )
            next_risk = propagate_risk(risk, next_step.exposure_score)
            next_steps = [*steps, next_step]
            next_visited = visited | {edge.target_entity_id}
            queue.append(
                (
                    edge.target_entity_id,
                    next_steps,
                    next_visited,
                    next_depth,
                    next_risk,
                )
            )
            expanded = True

        # Terminal path: no further expansion from this node (or depth cap).
        if not expanded and len(steps) > 1:
            found.append(_to_discovered(steps, risk))
            if not policy.allow_path(len(found)):
                break

    # Also accept single-node paths (seed only) when the seed has no outbound
    # edges — still evidence-backed, not fabricated.
    if not found:
        found.append(_to_discovered([seed_step], seed_step.exposure_score))

    return found


def _node_to_step(
    node: GraphNode,
    *,
    sequence: int,
    step_type: StepType,
    confidence: PathConfidence,
    relationship_type: str | None,
    inferred_from_step: int | None,
    kill_chain: KillChainMapping,
    extra_evidence: tuple[str, ...] = (),
) -> AttackStep:
    phase = node.kill_chain_phase
    if phase and kill_chain.index_of(phase) is None:
        phase = None
    evidence = tuple(dict.fromkeys([*node.evidence_refs, *extra_evidence]))
    return AttackStep(
        sequence=sequence,
        entity_id=node.entity_id,
        canonical_key=node.canonical_key,
        step_type=step_type,
        confidence=confidence,
        technique_id=node.technique_id,
        evidence_refs=evidence,
        relationship_type=relationship_type,
        kill_chain_phase=phase,
        observed_at=None,
        inferred_from_step=inferred_from_step,
        exposure_score=exposure_score_for(
            confidence,
            is_kev=node.is_kev,
            epss_probability=node.epss_probability,
        ),
    )


def _to_discovered(steps: list[AttackStep], risk: float) -> DiscoveredPath:
    techniques = tuple(
        dict.fromkeys(s.technique_id for s in steps if s.technique_id is not None)
    )
    actors = tuple(
        dict.fromkeys(
            s.canonical_key.split(":", 1)[1]
            for s in steps
            if s.canonical_key.startswith("group:")
        )
    )
    return DiscoveredPath(
        steps=tuple(steps),
        path_confidence=weakest_path_confidence([s.confidence for s in steps]),
        max_exposure_score=risk,
        technique_coverage=techniques,
        attributed_actors=actors,
    )


def build_graph_from_fusion(
    *,
    nodes: list[GraphNode],
    edges: list[GraphEdge],
) -> AttackGraph:
    """Assemble an `AttackGraph` from pre-validated fusion projections."""
    graph = AttackGraph()
    for node in nodes:
        graph.add_node(node)
    for edge in edges:
        graph.add_edge(edge)
    return graph
