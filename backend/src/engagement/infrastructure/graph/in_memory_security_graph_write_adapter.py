"""In-memory ISecurityGraphWritePort for engagement projection tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from engagement.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


@dataclass
class _Node:
    node_id: str
    organization_id: str
    node_kind: str
    source_domain: str
    source_entity_id: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Edge:
    edge_id: str
    organization_id: str
    source_key: str
    target_key: str
    relationship_kind: str
    attributes: dict[str, Any] = field(default_factory=dict)


class InMemorySecurityGraphWriteAdapter(ISecurityGraphWritePort):
    """Idempotent in-memory graph writer for engagement ontology."""

    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str, str], _Node] = {}
        self.edges: dict[tuple[str, str, str, str], _Edge] = {}
        self._seq = 0

    def _upsert_node(
        self,
        *,
        organization_id: str,
        node_kind: str,
        source_domain: str,
        source_entity_id: str,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        key = (organization_id, source_domain, source_entity_id)
        existing = self.nodes.get(key)
        if existing is not None:
            if attributes:
                existing.attributes.update(attributes)
            return existing.node_id
        self._seq += 1
        node_id = f"egn-{self._seq}"
        self.nodes[key] = _Node(
            node_id=node_id,
            organization_id=organization_id,
            node_kind=node_kind,
            source_domain=source_domain,
            source_entity_id=source_entity_id,
            attributes=dict(attributes or {}),
        )
        return node_id

    def _upsert_edge(
        self,
        *,
        organization_id: str,
        source_domain: str,
        source_entity_id: str,
        target_domain: str,
        target_entity_id: str,
        relationship_kind: str,
        attributes: dict[str, Any] | None = None,
    ) -> str:
        sk = f"{source_domain}:{source_entity_id}"
        tk = f"{target_domain}:{target_entity_id}"
        key = (organization_id, sk, relationship_kind, tk)
        existing = self.edges.get(key)
        if existing is not None:
            if attributes:
                existing.attributes.update(attributes)
            return existing.edge_id
        self._seq += 1
        edge_id = f"ege-{self._seq}"
        self.edges[key] = _Edge(
            edge_id=edge_id,
            organization_id=organization_id,
            source_key=sk,
            target_key=tk,
            relationship_kind=relationship_kind,
            attributes=dict(attributes or {}),
        )
        return edge_id

    async def project_engagement_node(
        self,
        *,
        organization_id: str,
        engagement_id: str,
        state: str | None = None,
        classification: str | None = None,
        window_start: str | None = None,
        window_end: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="engagement",
            source_domain="engagement",
            source_entity_id=engagement_id,
            attributes={
                "engagement_id": engagement_id,
                "state": state or "",
                "classification": classification or "",
                "window_start": window_start or "",
                "window_end": window_end or "",
            },
        )

    async def project_contains_operation(
        self,
        *,
        organization_id: str,
        engagement_id: str,
        operation_id: str,
        phase: str | None = None,
    ) -> None:
        await self.project_engagement_node(
            organization_id=organization_id, engagement_id=engagement_id
        )
        self._upsert_node(
            organization_id=organization_id,
            node_kind="operation",
            source_domain="operation",
            source_entity_id=operation_id,
            attributes={"operation_id": operation_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="engagement",
            source_entity_id=engagement_id,
            target_domain="operation",
            target_entity_id=operation_id,
            relationship_kind="contains_operation",
            attributes={"phase": phase or ""},
        )
