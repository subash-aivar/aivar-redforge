"""Stub ACL adapters for taskgraph Security Graph writes."""

from __future__ import annotations

from taskgraph.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


class StubTaskGraphGraphWriteAdapter(ISecurityGraphWritePort):
    def __init__(self) -> None:
        self.task_graph_nodes: list[dict[str, object]] = []
        self.task_nodes: list[dict[str, object]] = []
        self.graph_contains_edges: list[dict[str, object]] = []
        self.task_depends_edges: list[dict[str, object]] = []

    async def upsert_task_graph_node(
        self,
        *,
        tenant_id: str,
        graph_id: str,
        version: str,
    ) -> None:
        key = (tenant_id, graph_id)
        self.task_graph_nodes = [
            n for n in self.task_graph_nodes if (n["tenant_id"], n["graph_id"]) != key
        ]
        self.task_graph_nodes.append(
            {"tenant_id": tenant_id, "graph_id": graph_id, "version": version}
        )

    async def upsert_campaign_task_node(
        self,
        *,
        tenant_id: str,
        task_id: str,
        task_type: str,
        criticality: str,
    ) -> None:
        key = (tenant_id, task_id)
        self.task_nodes = [n for n in self.task_nodes if (n["tenant_id"], n["task_id"]) != key]
        self.task_nodes.append(
            {
                "tenant_id": tenant_id,
                "task_id": task_id,
                "task_type": task_type,
                "criticality": criticality,
            }
        )

    async def upsert_graph_contains_edge(
        self,
        *,
        tenant_id: str,
        graph_id: str,
        task_id: str,
        sequence: int,
    ) -> None:
        key = (tenant_id, graph_id, task_id)
        self.graph_contains_edges = [
            e
            for e in self.graph_contains_edges
            if (e["tenant_id"], e["graph_id"], e["task_id"]) != key
        ]
        self.graph_contains_edges.append(
            {
                "tenant_id": tenant_id,
                "graph_id": graph_id,
                "task_id": task_id,
                "sequence": sequence,
            }
        )

    async def upsert_task_depends_on_edge(
        self,
        *,
        tenant_id: str,
        from_task_id: str,
        to_task_id: str,
        predicate: str,
    ) -> None:
        key = (tenant_id, from_task_id, to_task_id)
        self.task_depends_edges = [
            e
            for e in self.task_depends_edges
            if (e["tenant_id"], e["from_task_id"], e["to_task_id"]) != key
        ]
        self.task_depends_edges.append(
            {
                "tenant_id": tenant_id,
                "from_task_id": from_task_id,
                "to_task_id": to_task_id,
                "predicate": predicate,
            }
        )
