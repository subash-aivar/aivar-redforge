from __future__ import annotations

import hashlib
from typing import Any


class InMemorySecurityGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, object]] = {}
        self.edges: set[tuple[str, str, str]] = set()

    def upsert_node(self, node_type: str, domain_id: str, properties: dict[str, object]) -> str:
        node_id = hashlib.sha256(f"{node_type}:{domain_id}".encode()).hexdigest()
        self.nodes[node_id] = {"node_type": node_type, **properties}
        return node_id

    def upsert_edge(self, from_id: str, edge_type: str, to_id: str) -> None:
        self.edges.add((from_id, edge_type, to_id))


class AutomationKGProjector:
    def __init__(self, graph: InMemorySecurityGraph | None = None) -> None:
        self.graph = graph or InMemorySecurityGraph()

    def project(self, event: Any) -> None:
        name = type(event).__name__
        if name == "PlaybookApproved":
            self.graph.upsert_node(
                "playbook",
                event.playbook_id,
                {
                    "tenant_id": event.tenant_id,
                    "status": "APPROVED",
                    "max_impact_level": event.max_impact_level,
                },
            )
        elif name == "AutomatedActionRecorded":
            node = self.graph.upsert_node(
                "automated_action",
                event.record_id,
                {
                    "tenant_id": event.tenant_id,
                    "execution_id": event.execution_id,
                    "action_type": event.action_type,
                    "connector_type": event.connector_type,
                    "outcome": event.outcome,
                },
            )
            playbook_node = hashlib.sha256(
                f"playbook:{getattr(event, 'playbook_id', event.execution_id)}".encode()
            ).hexdigest()
            self.graph.upsert_edge(playbook_node, "executed_action", node)
        elif name == "AutomationRolledBack":
            self.graph.upsert_edge(
                hashlib.sha256(f"automated_action:{event.original_record_id}".encode()).hexdigest(),
                "rolled_back_by",
                hashlib.sha256(f"automated_action:{event.rollback_id}".encode()).hexdigest(),
            )
