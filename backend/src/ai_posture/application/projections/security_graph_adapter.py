"""In-memory Security Graph write adapter — idempotent under event replay."""

from __future__ import annotations

from typing import Any

from ai_posture.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


class InMemorySecurityGraphAdapter(ISecurityGraphWritePort):
    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        self.applied_events: set[str] = set()

    async def upsert_node(
        self,
        *,
        tenant_id: str,
        node_type: str,
        node_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None:
        key = (tenant_id, node_type, node_key)
        if event_id in self.applied_events and key in self.nodes:
            # Idempotent replay: keep existing if same event already applied
            return
        self.nodes[key] = {
            "tenant_id": tenant_id,
            "node_type": node_type,
            "node_key": node_key,
            "properties": dict(properties),
            "last_event_id": event_id,
        }
        self.applied_events.add(event_id)

    async def upsert_edge(
        self,
        *,
        tenant_id: str,
        edge_type: str,
        from_key: str,
        to_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None:
        key = (tenant_id, edge_type, from_key, to_key)
        if event_id in self.applied_events and key in self.edges:
            return
        self.edges[key] = {
            "tenant_id": tenant_id,
            "edge_type": edge_type,
            "from_key": from_key,
            "to_key": to_key,
            "properties": dict(properties),
            "last_event_id": event_id,
        }
        self.applied_events.add(event_id)

    async def get_node(
        self, tenant_id: str, node_type: str, node_key: str
    ) -> dict[str, Any] | None:
        return self.nodes.get((tenant_id, node_type, node_key))

    async def list_edges(
        self, tenant_id: str, *, edge_type: str | None = None
    ) -> list[dict[str, Any]]:
        rows = [e for e in self.edges.values() if e["tenant_id"] == tenant_id]
        if edge_type is not None:
            rows = [e for e in rows if e["edge_type"] == edge_type]
        return rows
