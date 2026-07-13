"""Knowledge Graph projector for ConversationSession lifecycle events.

Projects completed ConversationSession objects into the KG as:
- One CONVERSATION_SESSION node
- One CONVERSATION_TURN node per turn
- CONVERSATION_SESSION_HAS_TURN edges (ordered)
- CONVERSATION_SESSION_TARGETS edge to the AI_TARGET node
- CONVERSATION_PART_OF_CAMPAIGN edge (if session.campaign_id is set)

Following the same post-commit isolation pattern as CampaignKnowledgeGraphProjector:
failures are caught and swallowed — a KG projection failure must never abort
or roll back a completed ConversationSession.
"""

from __future__ import annotations

import logging

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)
from redforge.domain.conversations.entity import ConversationSession
from redforge.domain.conversations.value_objects import ConversationOutcome

_log = logging.getLogger(__name__)


class ConversationKnowledgeGraphProjector:
    """Projects ConversationSession objects into the KnowledgeGraph."""

    def __init__(self, graph: KnowledgeGraph) -> None:
        self._graph = graph

    def project_session(self, session: ConversationSession) -> int:
        """Project session node + turn nodes + edges. Returns total nodes added."""
        try:
            return self._do_project(session)
        except Exception:
            _log.exception(
                "KG projection failed for ConversationSession %s — ignoring", session.id
            )
            return 0

    def _do_project(self, session: ConversationSession) -> int:
        session_id = str(session.id)
        target_id = str(session.target_id)
        nodes_added = 0

        # Ensure AI_TARGET stub exists so we can safely add edges to it
        if not self._graph.get_node(target_id):
            self._graph.add_node(GraphNode(
                node_id=target_id,
                node_type=NodeType.AI_TARGET,
                label=f"ai_target:{target_id}",
                metadata={"stub": "true"},
            ))
            nodes_added += 1

        # Session node
        metrics = session.metrics
        session_node = GraphNode(
            node_id=session_id,
            node_type=NodeType.CONVERSATION_SESSION,
            label=f"conversation:{session.strategy_type.value}",
            metadata={
                "strategy_type": session.strategy_type.value,
                "attack_category": session.attack_category,
                "status": session.status.value,
                "outcome": session.outcome.value if session.outcome else "",
                "total_turns": str(session.turn_count),
                "total_estimated_tokens": str(session.total_estimated_tokens),
                "success_rate": str(metrics.success_rate) if metrics else "0.0",
                "escalation_count": str(metrics.escalation_count) if metrics else "0",
            },
        )
        self._graph.add_node(session_node)
        nodes_added += 1

        # Session → Target edge
        self._graph.add_edge(GraphEdge(
            source_id=session_id,
            target_id=target_id,
            relationship=RelationshipType.CONVERSATION_SESSION_TARGETS,
            metadata={},
        ))

        # Campaign link (optional)
        if session.campaign_id:
            campaign_id = str(session.campaign_id)
            if not self._graph.get_node(campaign_id):
                self._graph.add_node(GraphNode(
                    node_id=campaign_id,
                    node_type=NodeType.CAMPAIGN,
                    label=f"campaign:{campaign_id}",
                    metadata={"stub": "true"},
                ))
                nodes_added += 1
            self._graph.add_edge(GraphEdge(
                source_id=session_id,
                target_id=campaign_id,
                relationship=RelationshipType.CONVERSATION_PART_OF_CAMPAIGN,
                metadata={},
            ))

        # Turn nodes + edges
        for turn in session.turns:
            turn_node_id = f"{session_id}:turn:{turn.turn_number}"
            turn_node = GraphNode(
                node_id=turn_node_id,
                node_type=NodeType.CONVERSATION_TURN,
                label=f"turn:{turn.turn_number}",
                metadata={
                    "turn_number": str(turn.turn_number),
                    "decision": turn.decision,
                    "evaluation_outcome": turn.evaluation_outcome,
                    "estimated_tokens": str(turn.estimated_tokens),
                    "is_error": str(turn.is_error),
                },
            )
            self._graph.add_node(turn_node)
            nodes_added += 1

            self._graph.add_edge(GraphEdge(
                source_id=session_id,
                target_id=turn_node_id,
                relationship=RelationshipType.CONVERSATION_SESSION_HAS_TURN,
                metadata={"order": str(turn.turn_number)},
            ))

        # Success finding edge (if session succeeded)
        if session.outcome == ConversationOutcome.SUCCESS:
            self._graph.add_edge(GraphEdge(
                source_id=session_id,
                target_id=target_id,
                relationship=RelationshipType.CONVERSATION_PRODUCED_FINDING,
                metadata={
                    "attack_category": session.attack_category,
                    "total_turns": str(session.turn_count),
                },
            ))

        return nodes_added
