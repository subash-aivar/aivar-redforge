"""In-memory ISecurityGraphWritePort for detection projection tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from detection.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort


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
    """Idempotent in-memory graph writer for detection ontology."""

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
        node_id = f"dn-{self._seq}"
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
        edge_id = f"de-{self._seq}"
        self.edges[key] = _Edge(
            edge_id=edge_id,
            organization_id=organization_id,
            source_key=sk,
            target_key=tk,
            relationship_kind=relationship_kind,
            attributes=dict(attributes or {}),
        )
        return edge_id

    async def project_detection_rule(
        self,
        *,
        organization_id: str,
        rule_id: str,
        rule_key: str,
        severity: str,
        confidence: str,
        lifecycle_state: str,
        version: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="detection_rule",
            source_domain="detection_rule",
            source_entity_id=rule_id,
            attributes={
                "rule_id": rule_id,
                "rule_key": rule_key,
                "severity": severity,
                "confidence": confidence,
                "lifecycle_state": lifecycle_state,
                "version": version or "",
            },
        )

    async def project_detection_pack(
        self,
        *,
        organization_id: str,
        pack_id: str,
        pack_key: str,
        pack_category: str,
        version: str,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="detection_pack",
            source_domain="detection_pack",
            source_entity_id=pack_id,
            attributes={
                "pack_id": pack_id,
                "pack_key": pack_key,
                "pack_category": pack_category,
                "version": version,
            },
        )

    async def project_detection_finding(
        self,
        *,
        organization_id: str,
        finding_id: str,
        state: str,
        severity: str,
        detected_at: str,
        mitre_technique: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="detection_finding",
            source_domain="detection_finding",
            source_entity_id=finding_id,
            attributes={
                "finding_id": finding_id,
                "state": state,
                "severity": severity,
                "detected_at": detected_at,
                "mitre_technique": mitre_technique or "",
            },
        )

    async def project_telemetry_source(
        self,
        *,
        organization_id: str,
        source_id: str,
        source_type: str,
        health_status: str,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="telemetry_source",
            source_domain="telemetry_source",
            source_entity_id=source_id,
            attributes={
                "source_id": source_id,
                "source_type": source_type,
                "health_status": health_status,
            },
        )

    async def project_mitre_technique(
        self,
        *,
        organization_id: str,
        technique_id: str,
        tactic: str | None = None,
        name: str | None = None,
    ) -> str | None:
        return self._upsert_node(
            organization_id=organization_id,
            node_kind="attack_technique",
            source_domain="attack_technique",
            source_entity_id=technique_id,
            attributes={
                "technique_id": technique_id,
                "tactic": tactic or "",
                "name": name or technique_id,
            },
        )

    async def project_detects(
        self,
        *,
        organization_id: str,
        rule_id: str,
        technique_id: str,
        confidence: str | None = None,
    ) -> None:
        await self.project_detection_rule(
            organization_id=organization_id,
            rule_id=rule_id,
            rule_key=rule_id,
            severity="Unknown",
            confidence=confidence or "Medium",
            lifecycle_state="Active",
        )
        await self.project_mitre_technique(
            organization_id=organization_id, technique_id=technique_id
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_rule",
            source_entity_id=rule_id,
            target_domain="attack_technique",
            target_entity_id=technique_id,
            relationship_kind="detects",
            attributes={"confidence": confidence or ""},
        )

    async def project_covers(
        self,
        *,
        organization_id: str,
        pack_id: str,
        rule_id: str,
        version: str | None = None,
        added_at: str | None = None,
    ) -> None:
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_pack",
            source_entity_id=pack_id,
            target_domain="detection_rule",
            target_entity_id=rule_id,
            relationship_kind="covers",
            attributes={"version": version or "", "added_at": added_at or ""},
        )

    async def project_produced(
        self,
        *,
        organization_id: str,
        rule_id: str,
        finding_id: str,
        version: str | None = None,
        execution_ref: str | None = None,
    ) -> None:
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_rule",
            source_entity_id=rule_id,
            target_domain="detection_finding",
            target_entity_id=finding_id,
            relationship_kind="produced",
            attributes={
                "version": version or "",
                "execution_ref": execution_ref or "",
            },
        )

    async def project_finding_on(
        self,
        *,
        organization_id: str,
        finding_id: str,
        asset_id: str,
        observed_at: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="asset",
            source_domain="asset",
            source_entity_id=asset_id,
            attributes={"asset_id": asset_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_finding",
            source_entity_id=finding_id,
            target_domain="asset",
            target_entity_id=asset_id,
            relationship_kind="finding_on",
            attributes={"observed_at": observed_at or ""},
        )

    async def project_finding_involves(
        self,
        *,
        organization_id: str,
        finding_id: str,
        identity_id: str,
        actor_role: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="identity",
            source_domain="identity",
            source_entity_id=identity_id,
            attributes={"identity_id": identity_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_finding",
            source_entity_id=finding_id,
            target_domain="identity",
            target_entity_id=identity_id,
            relationship_kind="finding_involves",
            attributes={"actor_role": actor_role or ""},
        )

    async def project_finding_correlates(
        self,
        *,
        organization_id: str,
        finding_id: str,
        instance_id: str,
        correlation_strength: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="vulnerability_instance",
            source_domain="vulnerability_instance",
            source_entity_id=instance_id,
            attributes={"instance_id": instance_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_finding",
            source_entity_id=finding_id,
            target_domain="vulnerability_instance",
            target_entity_id=instance_id,
            relationship_kind="finding_correlates",
            attributes={"correlation_strength": correlation_strength or ""},
        )

    async def project_finding_attributed(
        self,
        *,
        organization_id: str,
        finding_id: str,
        threat_actor_id: str,
        confidence: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="threat_actor",
            source_domain="threat_actor",
            source_entity_id=threat_actor_id,
            attributes={"threat_actor_id": threat_actor_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_finding",
            source_entity_id=finding_id,
            target_domain="threat_actor",
            target_entity_id=threat_actor_id,
            relationship_kind="finding_attributed",
            attributes={"confidence": confidence or ""},
        )

    async def project_queries(
        self,
        *,
        organization_id: str,
        rule_id: str,
        source_id: str,
        query_type: str | None = None,
    ) -> None:
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_rule",
            source_entity_id=rule_id,
            target_domain="telemetry_source",
            target_entity_id=source_id,
            relationship_kind="queries",
            attributes={"query_type": query_type or ""},
        )

    async def project_escalated_to(
        self,
        *,
        organization_id: str,
        finding_id: str,
        investigation_id: str,
        escalated_at: str | None = None,
    ) -> None:
        self._upsert_node(
            organization_id=organization_id,
            node_kind="investigation",
            source_domain="investigation",
            source_entity_id=investigation_id,
            attributes={"investigation_id": investigation_id},
        )
        self._upsert_edge(
            organization_id=organization_id,
            source_domain="detection_finding",
            source_entity_id=finding_id,
            target_domain="investigation",
            target_entity_id=investigation_id,
            relationship_kind="escalated_to",
            attributes={"escalated_at": escalated_at or ""},
        )
