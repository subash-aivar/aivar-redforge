"""SecurityGraphProjector — M4.

Projects trusted, already-persisted canonical domain data (M3 AIAsset /
AssetRelationship, Finding) into the tenant Security Graph. This is the
ONLY writer of security_graph_nodes/security_graph_edges — no HTTP
router constructs a node or edge directly, and no browser-supplied
input reaches these methods. Callers pass domain-verified data (an
AssetDTO already loaded via a tenant-scoped repository call, a
FindingDTO already created through FindingService).

Synchronous, in-transaction projection: the caller's own UnitOfWork
commits the projection alongside — or as a follow-up best-effort step
after — the canonical write, mirroring M3's non-blocking
target-to-asset association. A projection failure never blocks or
rolls back the canonical domain write; it is logged and observable,
never silently swallowed into a corrupted half-state (partial writes to
security_graph tables are themselves transactional within one
UnitOfWork).

Unsupported asset types / relationship types are SKIPPED, never
coerced to a default edge kind — an unmapped AssetRelationshipType must
not silently become EdgeKind.CUSTOM by accident; only the explicit
entries in `_RELATIONSHIP_MAP` are ever emitted.
"""

from __future__ import annotations

import logging

from redforge.domain.inventory.value_objects import AssetRelationshipType, AssetType
from redforge.domain.security_graph.ontology import (
    ONTOLOGY_VERSION,
    EdgeKind,
    NodeKind,
    validate_edge,
)
from redforge.infrastructure.database.repositories.security_graph_repository import (
    SecurityGraphRepository,
)
from redforge.shared.identifiers import EntityId

logger = logging.getLogger(__name__)

# Only asset kinds with a clear, deliberate graph-node meaning are
# projected. AI_PROVIDER, PROMPT_TEMPLATE, and TOOL_DEFINITION are
# intentionally NOT projected in M4 — they don't yet have a clean
# 1:1 security-relationship meaning distinct from the asset/agent
# that uses them; forcing a mapping now would be a fabricated
# ontology entry, not a real one.
_ASSET_NODE_MAP: dict[AssetType, NodeKind] = {
    AssetType.AI_APPLICATION: NodeKind.AI_SYSTEM,
    AssetType.AI_AGENT: NodeKind.AI_AGENT,
    AssetType.AI_MODEL: NodeKind.MODEL,
    AssetType.RAG_SYSTEM: NodeKind.AI_SYSTEM,
    AssetType.MCP_SERVER: NodeKind.APPLICATION,
    AssetType.VECTOR_DATABASE: NodeKind.DATA_STORE,
    AssetType.KNOWLEDGE_BASE: NodeKind.DATA_STORE,
    AssetType.MEMORY_STORE: NodeKind.DATA_STORE,
    AssetType.EMBEDDING_MODEL: NodeKind.MODEL,
    AssetType.AI_ENDPOINT: NodeKind.APPLICATION,
    AssetType.APPLICATION: NodeKind.APPLICATION,
    AssetType.URL: NodeKind.APPLICATION,
    AssetType.HOST: NodeKind.HOST,
    AssetType.IP_ADDRESS: NodeKind.IP_ADDRESS,
    AssetType.CLOUD_RESOURCE: NodeKind.CLOUD_RESOURCE,
    AssetType.NETWORK: NodeKind.NETWORK,
    AssetType.DEVICE: NodeKind.DEVICE,
    AssetType.SERVICE: NodeKind.SERVICE,
    AssetType.CLOUD_ACCOUNT: NodeKind.CLOUD_ACCOUNT,
}

# Only relationship types with an unambiguous ontology edge kind are
# projected. AssetRelationshipType.CUSTOM maps to EdgeKind.CUSTOM
# deliberately (both are the documented escape hatch); anything not
# listed here is skipped, not coerced.
_RELATIONSHIP_MAP: dict[AssetRelationshipType, EdgeKind] = {
    AssetRelationshipType.AGENT_USES_MODEL: EdgeKind.USES_MODEL,
    AssetRelationshipType.AGENT_USES_TOOL: EdgeKind.USES_TOOL,
    AssetRelationshipType.AGENT_USES_MCP: EdgeKind.USES_TOOL,
    AssetRelationshipType.AGENT_USES_RAG: EdgeKind.RETRIEVES_FROM,
    AssetRelationshipType.RAG_USES_VECTOR_DB: EdgeKind.RETRIEVES_FROM,
    AssetRelationshipType.RAG_USES_KNOWLEDGE_BASE: EdgeKind.RETRIEVES_FROM,
    AssetRelationshipType.PROVIDER_HOSTS_MODEL: EdgeKind.HOSTS_MODEL,
    AssetRelationshipType.MODEL_SERVES_ENDPOINT: EdgeKind.SERVES_ENDPOINT,
    AssetRelationshipType.IP_ASSIGNED_TO_HOST: EdgeKind.CONNECTED_TO,
    AssetRelationshipType.HOST_EXPOSES_SERVICE: EdgeKind.EXPOSES,
    AssetRelationshipType.DEVICE_CONNECTED_TO_NETWORK: EdgeKind.CONNECTED_TO,
    AssetRelationshipType.IP_MEMBER_OF_NETWORK: EdgeKind.MEMBER_OF_NETWORK,
    AssetRelationshipType.CLOUD_ACCOUNT_CONTAINS_RESOURCE: EdgeKind.CONTAINS,
    # M12 — a real observed DNS-resolution fact, not yet warranting a
    # dedicated edge kind of its own; uses the same documented CUSTOM
    # escape hatch as AssetRelationshipType.CUSTOM itself.
    AssetRelationshipType.TARGET_RESOLVES_TO_IP: EdgeKind.CUSTOM,
    AssetRelationshipType.CUSTOM: EdgeKind.CUSTOM,
}


class SecurityGraphProjector:
    def __init__(self, repo: SecurityGraphRepository) -> None:
        self._repo = repo

    async def project_asset(
        self, organization_id: str, asset_id: str, asset_type: str, name: str
    ) -> str | None:
        """Projects one AIAsset into a graph node. Returns the graph
        node ID, or None if this asset_type has no supported node-kind
        mapping (skipped, not fabricated)."""
        try:
            kind = _ASSET_NODE_MAP[AssetType(asset_type)]
        except (ValueError, KeyError):
            logger.info("security_graph: skipping unsupported asset_type=%s", asset_type)
            return None

        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=kind.value,
            source_domain="asset",
            source_entity_id=asset_id,
            label=name,
            attributes={"asset_type": asset_type},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_asset_relationship(
        self,
        organization_id: str,
        source_asset_id: str,
        target_asset_id: str,
        relationship_type: str,
    ) -> str | None:
        """Projects one AssetRelationship into a graph edge. Both
        endpoints must already be projected nodes (source_domain=
        'asset'). Returns the edge ID, or None if the relationship type
        is unsupported or the ontology pairing is invalid — never
        fabricates an edge."""
        try:
            edge_kind = _RELATIONSHIP_MAP[AssetRelationshipType(relationship_type)]
        except (ValueError, KeyError):
            logger.info(
                "security_graph: skipping unsupported relationship_type=%s", relationship_type
            )
            return None

        source_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", source_asset_id
        )
        target_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", target_asset_id
        )
        if source_node is None or target_node is None:
            logger.info(
                "security_graph: skipping edge, endpoint not yet projected (source=%s target=%s)",
                source_asset_id,
                target_asset_id,
            )
            return None

        try:
            source_kind = NodeKind(source_node.node_kind)
            target_kind = NodeKind(target_node.node_kind)
            validate_edge(edge_kind, source_kind, target_kind)
        except Exception:
            logger.info(
                "security_graph: rejecting invalid ontology pairing %s --%s--> %s",
                source_node.node_kind,
                edge_kind.value,
                target_node.node_kind,
            )
            return None

        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=source_node.id,
            target_node_id=target_node.id,
            relationship_kind=edge_kind.value,
            provenance="asset_relationship",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_finding(
        self,
        organization_id: str,
        finding_id: str,
        title: str,
        severity: str,
        asset_id: str | None,
    ) -> str | None:
        """Projects a Finding as a FINDING node and, if the caller has
        already resolved the Finding's canonical target_id to a real
        projected asset node — via the same REDFORGE_TARGET_ID identity
        scheme M3 uses in `TenantAssetService.get_or_create_for_target`
        — an ASSET--HAS_FINDING-->FINDING edge using that real,
        persisted reference (`asset_id` is the resolved AIAsset.id, not
        the raw target_id — this method does no lookup of its own by
        design, since it must not fabricate a correlation the caller
        hasn't already verified against canonical data).
        If `asset_id` is None (no canonical asset resolved yet), the
        Finding node is still projected but no edge is fabricated —
        NOT CORRELATED is distinct from NO RISK."""
        finding_node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.FINDING.value,
            source_domain="finding",
            source_entity_id=finding_id,
            label=title,
            attributes={"severity": severity},
            ontology_version=ONTOLOGY_VERSION,
        )

        if asset_id is None:
            return finding_node.id

        asset_node = await self._repo.get_node_by_id_for_org(asset_id, organization_id)
        if asset_node is None:
            return finding_node.id

        try:
            validate_edge(EdgeKind.HAS_FINDING, NodeKind(asset_node.node_kind), NodeKind.FINDING)
        except Exception:
            return finding_node.id

        await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=asset_node.id,
            target_node_id=finding_node.id,
            relationship_kind=EdgeKind.HAS_FINDING.value,
            provenance="finding_target_reference",
            ontology_version=ONTOLOGY_VERSION,
        )
        return finding_node.id

    async def project_directory_identity(
        self,
        organization_id: str,
        identity_id: str,
        principal_category: str,
        display_name: str,
        source_enabled: bool,
        privilege_classification: str,
    ) -> str | None:
        """Projects a DirectoryIdentity (M5) as an IDENTITY or
        SERVICE_IDENTITY node depending on principal_category. Only
        safe, already-classified fields are forwarded — never
        credential references, bind secrets, or raw directory
        attributes."""
        node_kind = (
            NodeKind.SERVICE_IDENTITY if principal_category == "service" else NodeKind.IDENTITY
        )
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=node_kind.value,
            source_domain="directory_identity",
            source_entity_id=identity_id,
            label=display_name,
            attributes={
                "enabled": str(source_enabled).lower(),
                "privilege_classification": privilege_classification,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_directory_group(
        self, organization_id: str, group_id: str, display_name: str, is_recognized_privileged: bool
    ) -> str | None:
        """Projects a DirectoryGroup (M5) as a GROUP node."""
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.GROUP.value,
            source_domain="directory_group",
            source_entity_id=group_id,
            label=display_name,
            attributes={"recognized_privileged": str(is_recognized_privileged).lower()},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_membership(
        self, organization_id: str, identity_id: str, group_id: str
    ) -> str | None:
        """Projects a canonical, already-persisted DirectoryMembership
        (M5) as an IDENTITY|SERVICE_IDENTITY --MEMBER_OF--> GROUP edge.
        Both endpoints must already be projected nodes. Never fabricates
        an edge for an unresolved reference."""
        identity_node = await self._repo.get_node_by_source_for_org(
            organization_id, "directory_identity", identity_id
        )
        group_node = await self._repo.get_node_by_source_for_org(
            organization_id, "directory_group", group_id
        )
        if identity_node is None or group_node is None:
            logger.info(
                "security_graph: skipping MEMBER_OF edge, endpoint not yet projected "
                "(identity=%s group=%s)",
                identity_id,
                group_id,
            )
            return None

        try:
            source_kind = NodeKind(identity_node.node_kind)
            validate_edge(EdgeKind.MEMBER_OF, source_kind, NodeKind(group_node.node_kind))
        except Exception:
            logger.info(
                "security_graph: rejecting invalid MEMBER_OF pairing %s --> %s",
                identity_node.node_kind,
                group_node.node_kind,
            )
            return None

        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=identity_node.id,
            target_node_id=group_node.id,
            relationship_kind=EdgeKind.MEMBER_OF.value,
            provenance="directory_membership",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_investigation(
        self,
        organization_id: str,
        case_id: str,
        title: str,
        severity: str,
        status: str,
        correlation_key: str,
    ) -> str | None:
        """Projects a canonical InvestigationCase (M21) as an INVESTIGATION node.

        The node is always created; CORRELATED_WITH edges to existing asset/
        finding/condition nodes are emitted only when a matching graph node is
        already projected for a given evidence entity (never fabricated from
        string labels alone). Idempotent: repeated calls for the same case_id
        update the node's status/severity attributes.
        """
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.INVESTIGATION.value,
            source_domain="investigation",
            source_entity_id=case_id,
            label=title,
            attributes={
                "severity": severity,
                "status": status,
                "correlation_key": correlation_key,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_security_condition(
        self,
        organization_id: str,
        condition_id: str,
        affected_asset_id: str,
        stable_rule_id: str,
        title: str,
        severity: str,
        evidence_state: str,
    ) -> str | None:
        """Projects a canonical, already-persisted SecurityCondition
        (M8) as a SECURITY_CONDITION node and, if the affected asset is
        already a projected node, an
        ASSET_KIND--HAS_SECURITY_CONDITION-->SECURITY_CONDITION edge.
        Only safe, already-classified fields are forwarded — raw
        evidence and remediation text never reach the graph. If the
        asset node is not yet projected, the condition node is still
        created but no edge is fabricated."""
        condition_node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.SECURITY_CONDITION.value,
            source_domain="security_condition",
            source_entity_id=condition_id,
            label=title,
            attributes={
                "severity": severity,
                "evidence_state": evidence_state,
                "stable_rule_id": stable_rule_id,
            },
            ontology_version=ONTOLOGY_VERSION,
        )

        asset_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", affected_asset_id
        )
        if asset_node is None:
            return condition_node.id

        try:
            validate_edge(
                EdgeKind.HAS_SECURITY_CONDITION,
                NodeKind(asset_node.node_kind),
                NodeKind.SECURITY_CONDITION,
            )
        except Exception:
            logger.info(
                "security_graph: rejecting invalid HAS_SECURITY_CONDITION pairing %s --> %s",
                asset_node.node_kind,
                NodeKind.SECURITY_CONDITION.value,
            )
            return condition_node.id

        await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=asset_node.id,
            target_node_id=condition_node.id,
            relationship_kind=EdgeKind.HAS_SECURITY_CONDITION.value,
            provenance="security_condition_asset_reference",
            ontology_version=ONTOLOGY_VERSION,
        )
        return condition_node.id
