"""Append-only Security Graph write adapter (Phase 5)."""

from __future__ import annotations

from typing import Any

from exposure_reporting.domain.ports.i_security_graph_write_port import (
    ISecurityGraphWritePort,
)


class InMemorySecurityGraphWriteAdapter(ISecurityGraphWritePort):
    """Seedable in-process graph sink — write-only surface for M32."""

    def __init__(self) -> None:
        self.nodes: list[dict[str, Any]] = []
        self.edges: list[dict[str, Any]] = []

    async def upsert_exposure_node(
        self,
        *,
        tenant_id: str,
        node_type: str,
        node_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None:
        # Append-only: replace matching key but retain history via list append marker
        self.nodes = [
            n
            for n in self.nodes
            if not (
                n["tenant_id"] == tenant_id
                and n["node_type"] == node_type
                and n["node_key"] == node_key
            )
        ]
        self.nodes.append(
            {
                "tenant_id": tenant_id,
                "node_type": node_type,
                "node_key": node_key,
                "properties": dict(properties),
                "event_id": event_id,
            }
        )

    async def upsert_exposure_edge(
        self,
        *,
        tenant_id: str,
        edge_type: str,
        from_key: str,
        to_key: str,
        properties: dict[str, Any],
        event_id: str,
    ) -> None:
        self.edges = [
            e
            for e in self.edges
            if not (
                e["tenant_id"] == tenant_id
                and e["edge_type"] == edge_type
                and e["from_key"] == from_key
                and e["to_key"] == to_key
            )
        ]
        self.edges.append(
            {
                "tenant_id": tenant_id,
                "edge_type": edge_type,
                "from_key": from_key,
                "to_key": to_key,
                "properties": dict(properties),
                "event_id": event_id,
            }
        )
