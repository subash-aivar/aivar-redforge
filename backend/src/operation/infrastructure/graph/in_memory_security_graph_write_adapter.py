"""In-memory ISecurityGraphWritePort for operation projection tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from operation.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


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
    """Idempotent in-memory graph writer for operation ontology."""

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
        node_id = f"opn-{self._seq}"
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
        edge_id = f"ope-{self._seq}"
        self.edges[key] = _Edge(
            edge_id=edge_id,
            organization_id=organization_id,
            source_key=sk,
            target_key=tk,
            relationship_kind=relationship_kind,
            attributes=dict(attributes or {}),
        )
        return edge_id

    async def project_operation_node(
        self,
        *,
        organization_id: str,
        operation_id: str,
        classification: str | None = None,
        risk: str | None = None,
        state: str | None = None,
        engagement_id: str | None = None,
        name: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="operation",
            source_domain="operation",
            source_entity_id=operation_id,
            attributes={
                "operation_id": operation_id,
                "classification": classification or "",
                "risk": risk or "",
                "state": state or "",
                "engagement_id": engagement_id or "",
                "name": name or "",
            },
        )

    async def project_executed_action(
        self,
        *,
        organization_id: str,
        operation_id: str,
        action_id: str,
        sequence_number: int | None = None,
    ) -> None:
        await self.project_operation_node(
            organization_id=organization_id, operation_id=operation_id
        )
        self._upsert_node(
            organization_id=organization_id,
            node_kind="attack_action",
            source_domain="attack_action",
            source_entity_id=action_id,
            attributes={"action_id": action_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="operation",
            source_entity_id=operation_id,
            target_domain="attack_action",
            target_entity_id=action_id,
            relationship_kind="executed_action",
            attributes={"sequence_number": sequence_number if sequence_number is not None else 0},
        )
