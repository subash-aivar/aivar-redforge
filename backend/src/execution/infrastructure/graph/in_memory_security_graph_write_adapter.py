"""In-memory ISecurityGraphWritePort for execution projection tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from execution.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


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
    """Idempotent in-memory graph writer for execution / red-team ontology."""

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
        node_id = f"en-{self._seq}"
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
        edge_id = f"ee-{self._seq}"
        self.edges[key] = _Edge(
            edge_id=edge_id,
            organization_id=organization_id,
            source_key=sk,
            target_key=tk,
            relationship_kind=relationship_kind,
            attributes=dict(attributes or {}),
        )
        return edge_id

    def clear(self) -> None:
        self.nodes.clear()
        self.edges.clear()
        self._seq = 0

    async def project_attack_action_node(
        self,
        *,
        organization_id: str,
        action_id: str,
        technique_ref: str | None = None,
        state: str | None = None,
        timestamp: str | None = None,
        action_hash: str | None = None,
        operation_id: str | None = None,
        engagement_id: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="attack_action",
            source_domain="attack_action",
            source_entity_id=action_id,
            attributes={
                "action_id": action_id,
                "technique_ref": technique_ref or "",
                "state": state or "",
                "timestamp": timestamp or "",
                "action_hash": action_hash or "",
                "operation_id": operation_id or "",
                "engagement_id": engagement_id or "",
            },
        )

    async def project_execution_worker_node(
        self,
        *,
        organization_id: str,
        worker_id: str,
        worker_type: str | None = None,
        trust_level: str | None = None,
        capabilities: list[str] | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="execution_worker",
            source_domain="execution_worker",
            source_entity_id=worker_id,
            attributes={
                "worker_id": worker_id,
                "worker_type": worker_type or "",
                "trust_level": trust_level or "",
                "capabilities": list(capabilities or []),
            },
        )

    async def project_payload_node(
        self,
        *,
        organization_id: str,
        payload_id: str,
        payload_type: str | None = None,
        impact_ceiling: str | None = None,
        version: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="payload",
            source_domain="payload",
            source_entity_id=payload_id,
            attributes={
                "payload_id": payload_id,
                "payload_type": payload_type or "",
                "impact_ceiling": impact_ceiling or "",
                "version": version or "",
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
        await self.project_attack_action_node(
            organization_id=organization_id, action_id=action_id, operation_id=operation_id
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
            source_domain="operation",
            source_entity_id=operation_id,
            target_domain="attack_action",
            target_entity_id=action_id,
            relationship_kind="executed_action",
            attributes={"sequence_number": sequence_number if sequence_number is not None else 0},
        )

    async def project_used_technique(
        self,
        *,
        organization_id: str,
        action_id: str,
        technique_id: str,
        success: bool | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="attack_technique",
            source_domain="attack_technique",
            source_entity_id=technique_id,
            attributes={"technique_id": technique_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="attack_technique",
            target_entity_id=technique_id,
            relationship_kind="used_technique",
            attributes={"success": "" if success is None else str(success)},
        )

    async def project_executed_by(
        self,
        *,
        organization_id: str,
        action_id: str,
        worker_id: str,
        worker_trust_level: str | None = None,
    ) -> None:
        await self.project_execution_worker_node(
            organization_id=organization_id,
            worker_id=worker_id,
            trust_level=worker_trust_level,
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="execution_worker",
            target_entity_id=worker_id,
            relationship_kind="executed_by",
            attributes={"worker_trust_level": worker_trust_level or ""},
        )

    async def project_targeted(
        self,
        *,
        organization_id: str,
        action_id: str,
        asset_id: str,
        impact_observed: str | None = None,
        asset_kind: str = "asset",
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind=asset_kind,
            source_domain="asset",
            source_entity_id=asset_id,
            attributes={"asset_id": asset_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="asset",
            target_entity_id=asset_id,
            relationship_kind="targeted",
            attributes={"impact_observed": impact_observed or ""},
        )

    async def project_used_payload(
        self,
        *,
        organization_id: str,
        action_id: str,
        payload_id: str,
        payload_version: str | None = None,
    ) -> None:
        await self.project_payload_node(
            organization_id=organization_id,
            payload_id=payload_id,
            version=payload_version,
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="payload",
            target_entity_id=payload_id,
            relationship_kind="used_payload",
            attributes={"payload_version": payload_version or ""},
        )

    async def project_caught_by_detection(
        self,
        *,
        organization_id: str,
        action_id: str,
        rule_id: str,
        detected_at: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="detection_rule",
            source_domain="detection_rule",
            source_entity_id=rule_id,
            attributes={"rule_id": rule_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="detection_rule",
            target_entity_id=rule_id,
            relationship_kind="caught_by_detection",
            attributes={
                "detected_at": detected_at or "",
                "finding_id": finding_id or "",
            },
        )

    async def project_evaded_detection(
        self,
        *,
        organization_id: str,
        action_id: str,
        rule_id: str,
        evaluated_at: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="detection_rule",
            source_domain="detection_rule",
            source_entity_id=rule_id,
            attributes={"rule_id": rule_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="detection_rule",
            target_entity_id=rule_id,
            relationship_kind="evaded_detection",
            attributes={"evaluated_at": evaluated_at or ""},
        )

    async def project_produced_finding(
        self,
        *,
        organization_id: str,
        action_id: str,
        finding_id: str,
        finding_type: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="detection_finding",
            source_domain="detection_finding",
            source_entity_id=finding_id,
            attributes={"finding_id": finding_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="attack_action",
            source_entity_id=action_id,
            target_domain="detection_finding",
            target_entity_id=finding_id,
            relationship_kind="produced_finding",
            attributes={"finding_type": finding_type or ""},
        )
