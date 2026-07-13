"""AgentKnowledgeGraphProjector — projects agent and MCP session state into KG.

Projects from domain aggregates (AgentSession, MCPSession) into the
application-layer knowledge graph. Called as a non-fatal side effect after
each session completes (wrapped in contextlib.suppress in the engine).

Projection model:
  AGENT_SESSION → AGENT_SESSION_TARGETS → AI_TARGET
  AGENT_SESSION → AGENT_SESSION_INVOKED_TOOL → TOOL_INVOCATION (blocked/escalated)
  AGENT_SESSION → AGENT_HAS_TOOL → TOOL (per unique tool name)
  MCP_SESSION → MCP_SESSION_TARGETS → AI_TARGET
  MCP_SERVER → MCP_SERVER_HAS_RESOURCE → MCP_RESOURCE
  MCP_SERVER → MCP_SERVER_EXPOSES_TOOL → TOOL

All node IDs are deterministic so re-projection is idempotent (add_node
overwrites in-memory). Edges are NOT deduplicated by the store — callers
must not call this projector multiple times for the same session.

Domain layer is never imported here (ADR-0001). Only aggregate IDs and
primitive attributes are read via public properties.
"""

from __future__ import annotations

import contextlib
import json
from typing import TYPE_CHECKING

from redforge.application.knowledge_graph import (
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NodeType,
    RelationshipType,
)

if TYPE_CHECKING:
    from redforge.domain.agents.entity import AgentSession, MCPSession


def _add(kg: KnowledgeGraph, node: GraphNode) -> None:
    kg.add_node(node)


def _link(kg: KnowledgeGraph, source_id: str, target_id: str, rel: RelationshipType) -> None:
    kg.add_edge(GraphEdge(source_id=source_id, target_id=target_id, relationship=rel))


class AgentKnowledgeGraphProjector:
    """Projects AgentSession and MCPSession state into the KnowledgeGraph.

    Injected into AgentValidationEngine and MCPValidationEngine.
    """

    def __init__(self, knowledge_graph: KnowledgeGraph) -> None:
        self._kg = knowledge_graph

    # ── Public API ────────────────────────────────────────────────────────────

    def project_agent_session(self, session: AgentSession) -> None:
        session_id = str(session.id)
        target_id = str(session.target_id)
        org_id = str(session.organization_id)

        _add(self._kg, GraphNode(
            node_id=session_id,
            node_type=NodeType.AGENT_SESSION,
            label=f"AgentSession:{session.agent_id}",
            metadata={
                "organization_id": org_id,
                "agent_id": session.agent_id,
                "status": session.status.value,
                "outcome": session.outcome.value if session.outcome else "",
                "attack_vectors": ",".join(v.value for v in session.attack_vectors),
                "succeeded_vectors": ",".join(session.succeeded_vectors),
                "invocation_count": str(session.invocation_count),
                "failure_reason": session.failure_reason or "",
            },
        ))

        _add(self._kg, GraphNode(
            node_id=target_id,
            node_type=NodeType.AI_TARGET,
            label=f"Target:{target_id}",
            metadata={"organization_id": org_id},
        ))
        _link(self._kg, session_id, target_id, RelationshipType.AGENT_SESSION_TARGETS)

        seen_tools: set[str] = set()
        for inv in session.invocations:
            if inv.status in ("blocked", "escalated", "tampered", "looped"):
                inv_node_id = f"tool_inv:{inv.invocation_id}"
                _add(self._kg, GraphNode(
                    node_id=inv_node_id,
                    node_type=NodeType.TOOL_INVOCATION,
                    label=f"ToolInvocation:{inv.tool_name}",
                    metadata={
                        "tool_name": inv.tool_name,
                        "status": inv.status,
                        "attack_vector": inv.attack_vector,
                        "depth": str(inv.depth),
                        "error": inv.error or "",
                    },
                ))
                _link(self._kg, session_id, inv_node_id,
                      RelationshipType.AGENT_SESSION_INVOKED_TOOL)

            if inv.tool_name not in seen_tools:
                seen_tools.add(inv.tool_name)
                tool_node_id = f"tool:{inv.tool_name}"
                _add(self._kg, GraphNode(
                    node_id=tool_node_id,
                    node_type=NodeType.TOOL,
                    label=f"Tool:{inv.tool_name}",
                    metadata={"name": inv.tool_name},
                ))
                _link(self._kg, session_id, tool_node_id, RelationshipType.AGENT_HAS_TOOL)

        if session.succeeded_vectors:
            path_node_id = f"attack_path:agent:{session_id}"
            _add(self._kg, GraphNode(
                node_id=path_node_id,
                node_type=NodeType.ATTACK_PATH,
                label=f"AttackPath:AgentSession:{session.agent_id}",
                metadata={
                    "vectors": ",".join(session.succeeded_vectors),
                    "session_id": session_id,
                },
            ))
            _link(self._kg, session_id, path_node_id, RelationshipType.ATTACK_PATH_THROUGH)

    def project_mcp_session(self, session: MCPSession) -> None:
        session_id = str(session.id)
        target_id = str(session.target_id)
        org_id = str(session.organization_id)
        server_node_id = f"mcp_server:{session.mcp_server_id}"

        _add(self._kg, GraphNode(
            node_id=session_id,
            node_type=NodeType.MCP_SESSION,
            label=f"MCPSession:{session.mcp_server_id}",
            metadata={
                "organization_id": org_id,
                "mcp_server_id": session.mcp_server_id,
                "status": session.status.value,
                "outcome": session.outcome.value if session.outcome else "",
                "total_interactions": str(len(session.interactions)),
                "attack_vectors": ",".join(v.value for v in session.attack_vectors),
                "succeeded_vectors": ",".join(session.succeeded_vectors),
            },
        ))

        _add(self._kg, GraphNode(
            node_id=server_node_id,
            node_type=NodeType.MCP_SERVER,
            label=f"MCPServer:{session.mcp_server_id}",
            metadata={"mcp_server_id": session.mcp_server_id},
        ))

        _add(self._kg, GraphNode(
            node_id=target_id,
            node_type=NodeType.AI_TARGET,
            label=f"Target:{target_id}",
            metadata={"organization_id": org_id},
        ))
        _link(self._kg, session_id, target_id, RelationshipType.MCP_SESSION_TARGETS)

        seen_resources: set[str] = set()
        seen_tools: set[str] = set()
        for interaction in session.interactions:
            with contextlib.suppress(Exception):
                params = json.loads(interaction.params or "{}")

                if interaction.method == "resources/read":
                    uri = params.get("uri", "")
                    if uri and uri not in seen_resources:
                        seen_resources.add(uri)
                        res_node_id = f"mcp_resource:{session.mcp_server_id}:{uri}"
                        _add(self._kg, GraphNode(
                            node_id=res_node_id,
                            node_type=NodeType.MCP_RESOURCE,
                            label=f"MCPResource:{uri}",
                            metadata={"uri": uri, "mcp_server_id": session.mcp_server_id},
                        ))
                        _link(self._kg, server_node_id, res_node_id,
                              RelationshipType.MCP_SERVER_HAS_RESOURCE)

                elif interaction.method == "tools/call":
                    tool_name = params.get("name", "")
                    if tool_name and tool_name not in seen_tools:
                        seen_tools.add(tool_name)
                        tool_node_id = f"tool:{tool_name}"
                        _add(self._kg, GraphNode(
                            node_id=tool_node_id,
                            node_type=NodeType.TOOL,
                            label=f"Tool:{tool_name}",
                            metadata={"name": tool_name},
                        ))
                        _link(self._kg, server_node_id, tool_node_id,
                              RelationshipType.MCP_SERVER_EXPOSES_TOOL)

        if session.succeeded_vectors:
            path_node_id = f"attack_path:mcp:{session_id}"
            _add(self._kg, GraphNode(
                node_id=path_node_id,
                node_type=NodeType.ATTACK_PATH,
                label=f"AttackPath:MCPSession:{session.mcp_server_id}",
                metadata={
                    "vectors": ",".join(session.succeeded_vectors),
                    "session_id": session_id,
                },
            ))
            _link(self._kg, session_id, path_node_id, RelationshipType.ATTACK_PATH_THROUGH)
