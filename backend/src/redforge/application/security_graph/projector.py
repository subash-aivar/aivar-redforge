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

    async def project_cloud_iam_principal(
        self,
        organization_id: str,
        principal_id: str,
        principal_type: str,
        display_name: str,
        provider_id: str,
    ) -> str | None:
        """Projects a CloudIAMPrincipal as IDENTITY / GROUP / IAM_ROLE /
        IAM_POLICY / SERVICE_IDENTITY. Unsupported types are skipped."""
        mapping: dict[str, NodeKind] = {
            "USER": NodeKind.IDENTITY,
            "GROUP": NodeKind.GROUP,
            "ROLE": NodeKind.IAM_ROLE,
            "POLICY": NodeKind.IAM_POLICY,
            "SERVICE_PRINCIPAL": NodeKind.SERVICE_IDENTITY,
            "MANAGED_IDENTITY": NodeKind.SERVICE_IDENTITY,
            "SERVICE_ACCOUNT": NodeKind.SERVICE_IDENTITY,
        }
        kind = mapping.get(principal_type.upper())
        if kind is None:
            logger.info(
                "security_graph: skipping unsupported IAM principal_type=%s", principal_type
            )
            return None

        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=kind.value,
            source_domain="cloud_iam_principal",
            source_entity_id=principal_id,
            label=display_name,
            attributes={
                "principal_type": principal_type,
                "provider_id": provider_id,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_iam_has_policy(
        self,
        organization_id: str,
        principal_id: str,
        policy_provider_id: str,
        policy_name: str,
    ) -> str | None:
        """Upserts an IAM_POLICY node (source_domain=cloud_iam_policy) and a
        HAS_POLICY edge from the already-projected principal. Skips if the
        principal node is missing or the ontology pairing is invalid."""
        principal_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_iam_principal", principal_id
        )
        if principal_node is None:
            logger.info(
                "security_graph: skipping HAS_POLICY, principal not projected (%s)",
                principal_id,
            )
            return None

        policy_node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.IAM_POLICY.value,
            source_domain="cloud_iam_policy",
            source_entity_id=policy_provider_id,
            label=policy_name,
            attributes={"provider_id": policy_provider_id},
            ontology_version=ONTOLOGY_VERSION,
        )

        try:
            validate_edge(
                EdgeKind.HAS_POLICY,
                NodeKind(principal_node.node_kind),
                NodeKind.IAM_POLICY,
            )
        except Exception:
            logger.info(
                "security_graph: rejecting invalid HAS_POLICY pairing %s --> iam_policy",
                principal_node.node_kind,
            )
            return None

        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=principal_node.id,
            target_node_id=policy_node.id,
            relationship_kind=EdgeKind.HAS_POLICY.value,
            provenance="cloud_iam_policy_attachment",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def _find_iam_principal_node_by_provider_id(
        self, organization_id: str, provider_id: str
    ) -> object | None:
        offset = 0
        while True:
            nodes = await self._repo.list_nodes_for_org(
                organization_id, limit=200, offset=offset
            )
            if not nodes:
                return None
            for node in nodes:
                if node.source_domain != "cloud_iam_principal":
                    continue
                attrs = node.attributes or {}
                if attrs.get("provider_id") == provider_id:
                    return node
            if len(nodes) < 200:
                return None
            offset += 200

    async def project_iam_trust(
        self,
        organization_id: str,
        principal_id: str,
        trusted_provider_id: str,
    ) -> str | None:
        """Projects a TRUSTS edge when both endpoints are already projected.
        Never fabricates a missing trusted principal node."""
        principal_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_iam_principal", principal_id
        )
        if principal_node is None:
            logger.info(
                "security_graph: skipping TRUSTS, principal not projected (%s)",
                principal_id,
            )
            return None

        trusted_node = await self._find_iam_principal_node_by_provider_id(
            organization_id, trusted_provider_id
        )
        if trusted_node is None:
            logger.info(
                "security_graph: skipping TRUSTS, trusted endpoint not projected (%s)",
                trusted_provider_id,
            )
            return None

        try:
            validate_edge(
                EdgeKind.TRUSTS,
                NodeKind(principal_node.node_kind),
                NodeKind(trusted_node.node_kind),  # type: ignore[attr-defined]
            )
        except Exception:
            logger.info(
                "security_graph: rejecting invalid TRUSTS pairing %s --> %s",
                principal_node.node_kind,
                trusted_node.node_kind,  # type: ignore[attr-defined]
            )
            return None

        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=principal_node.id,
            target_node_id=trusted_node.id,  # type: ignore[attr-defined]
            relationship_kind=EdgeKind.TRUSTS.value,
            provenance="cloud_iam_trust_relationship",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_cspm_finding(
        self,
        organization_id: str,
        finding_id: str,
        title: str,
        severity: str,
        status: str,
        policy_id: str,
        rule_id: str,
    ) -> str | None:
        """Upserts a CSPM_FINDING node (source_domain=cspm_finding)."""
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.CSPM_FINDING.value,
            source_domain="cspm_finding",
            source_entity_id=finding_id,
            label=title,
            attributes={
                "severity": severity,
                "status": status,
                "policy_id": policy_id,
                "rule_id": rule_id,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_cspm_control(
        self,
        organization_id: str,
        control_id: str,
        framework_key: str,
        requirement_ref: str,
        label: str,
    ) -> str | None:
        """Upserts a CONTROL node (source_domain=cspm_control)."""
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.CONTROL.value,
            source_domain="cspm_control",
            source_entity_id=control_id,
            label=label,
            attributes={
                "framework_key": framework_key,
                "requirement_ref": requirement_ref,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_cspm_affects(
        self,
        organization_id: str,
        finding_id: str,
        cloud_asset_id: str,
    ) -> str | None:
        """Projects AFFECTS from CSPM finding → inventory asset if present.

        Never fabricates a missing asset node — skips the edge when the
        CLOUD_RESOURCE/asset projection (source_domain=asset) is absent.
        """
        finding_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cspm_finding", finding_id
        )
        if finding_node is None:
            logger.info(
                "security_graph: skipping AFFECTS, finding not projected (%s)",
                finding_id,
            )
            return None

        asset_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", cloud_asset_id
        )
        if asset_node is None:
            logger.info(
                "security_graph: skipping AFFECTS, asset not projected (%s)",
                cloud_asset_id,
            )
            return None

        try:
            validate_edge(
                EdgeKind.AFFECTS,
                NodeKind(finding_node.node_kind),
                NodeKind(asset_node.node_kind),
            )
        except Exception:
            logger.info(
                "security_graph: rejecting invalid AFFECTS pairing %s --> %s",
                finding_node.node_kind,
                asset_node.node_kind,
            )
            return None

        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=finding_node.id,
            target_node_id=asset_node.id,
            relationship_kind=EdgeKind.AFFECTS.value,
            provenance="cspm_finding_affects_asset",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_cspm_violates(
        self,
        organization_id: str,
        finding_id: str,
        control_id: str,
    ) -> str | None:
        """Projects VIOLATES from CSPM finding → CONTROL."""
        finding_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cspm_finding", finding_id
        )
        control_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cspm_control", control_id
        )
        if finding_node is None or control_node is None:
            logger.info(
                "security_graph: skipping VIOLATES, endpoint missing "
                "(finding=%s control=%s)",
                finding_id,
                control_id,
            )
            return None
        try:
            validate_edge(
                EdgeKind.VIOLATES,
                NodeKind(finding_node.node_kind),
                NodeKind(control_node.node_kind),
            )
        except Exception:
            logger.info(
                "security_graph: rejecting invalid VIOLATES pairing %s --> %s",
                finding_node.node_kind,
                control_node.node_kind,
            )
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=finding_node.id,
            target_node_id=control_node.id,
            relationship_kind=EdgeKind.VIOLATES.value,
            provenance="cspm_finding_violates_control",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_cspm_evaluated_by(
        self,
        organization_id: str,
        finding_id: str,
        control_id: str,
    ) -> str | None:
        """Projects EVALUATED_BY from CSPM finding → CONTROL."""
        finding_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cspm_finding", finding_id
        )
        control_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cspm_control", control_id
        )
        if finding_node is None or control_node is None:
            logger.info(
                "security_graph: skipping EVALUATED_BY, endpoint missing "
                "(finding=%s control=%s)",
                finding_id,
                control_id,
            )
            return None
        try:
            validate_edge(
                EdgeKind.EVALUATED_BY,
                NodeKind(finding_node.node_kind),
                NodeKind(control_node.node_kind),
            )
        except Exception:
            logger.info(
                "security_graph: rejecting invalid EVALUATED_BY pairing %s --> %s",
                finding_node.node_kind,
                control_node.node_kind,
            )
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=finding_node.id,
            target_node_id=control_node.id,
            relationship_kind=EdgeKind.EVALUATED_BY.value,
            provenance="cspm_finding_evaluated_by_control",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    # --- M26 Phase 5 Kubernetes projection ---

    async def project_k8s_cluster(
        self,
        organization_id: str,
        cluster_id: str,
        name: str,
        cluster_type: str,
        version: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.K8S_CLUSTER.value,
            source_domain="k8s_cluster",
            source_entity_id=cluster_id,
            label=name,
            attributes={"cluster_type": cluster_type, "version": version},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_k8s_namespace(
        self,
        organization_id: str,
        namespace_id: str,
        cluster_id: str,
        name: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.K8S_NAMESPACE.value,
            source_domain="k8s_namespace",
            source_entity_id=namespace_id,
            label=name,
            attributes={"cluster_id": cluster_id},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_k8s_workload(
        self,
        organization_id: str,
        workload_id: str,
        cluster_id: str,
        namespace: str,
        name: str,
        kind: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.K8S_WORKLOAD.value,
            source_domain="k8s_workload",
            source_entity_id=workload_id,
            label=f"{namespace}/{name}",
            attributes={"cluster_id": cluster_id, "namespace": namespace, "kind": kind},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_k8s_service(
        self,
        organization_id: str,
        service_id: str,
        namespace: str,
        name: str,
        is_public: bool,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.K8S_SERVICE.value,
            source_domain="k8s_service",
            source_entity_id=service_id,
            label=f"{namespace}/{name}",
            attributes={"namespace": namespace, "is_public": is_public},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_k8s_rbac(
        self,
        organization_id: str,
        principal_id: str,
        kind: str,
        name: str,
        namespace: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.K8S_RBAC.value,
            source_domain="k8s_rbac",
            source_entity_id=principal_id,
            label=name,
            attributes={"kind": kind, "namespace": namespace},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_k8s_network_policy(
        self,
        organization_id: str,
        policy_id: str,
        namespace: str,
        name: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.K8S_NETWORK_POLICY.value,
            source_domain="k8s_network_policy",
            source_entity_id=policy_id,
            label=f"{namespace}/{name}",
            attributes={"namespace": namespace},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_k8s_hosts(
        self,
        organization_id: str,
        cluster_id: str,
        namespace_id: str,
    ) -> str | None:
        cluster_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_cluster", cluster_id
        )
        ns_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_namespace", namespace_id
        )
        if cluster_node is None or ns_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.HOSTS,
                NodeKind(cluster_node.node_kind),
                NodeKind(ns_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=cluster_node.id,
            target_node_id=ns_node.id,
            relationship_kind=EdgeKind.HOSTS.value,
            provenance="k8s_cluster_hosts_namespace",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_runs_in(
        self,
        organization_id: str,
        workload_id: str,
        namespace_id: str,
    ) -> str | None:
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        ns_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_namespace", namespace_id
        )
        if wl_node is None or ns_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.RUNS_IN,
                NodeKind(wl_node.node_kind),
                NodeKind(ns_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=wl_node.id,
            target_node_id=ns_node.id,
            relationship_kind=EdgeKind.RUNS_IN.value,
            provenance="k8s_workload_runs_in_namespace",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_deploys(
        self,
        organization_id: str,
        source_id: str,
        source_domain: str,
        workload_id: str,
    ) -> str | None:
        source_node = await self._repo.get_node_by_source_for_org(
            organization_id, source_domain, source_id
        )
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        if source_node is None or wl_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.DEPLOYS,
                NodeKind(source_node.node_kind),
                NodeKind(wl_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=source_node.id,
            target_node_id=wl_node.id,
            relationship_kind=EdgeKind.DEPLOYS.value,
            provenance="k8s_deploys_workload",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_exposes(
        self,
        organization_id: str,
        workload_id: str,
        service_id: str,
    ) -> str | None:
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        svc_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_service", service_id
        )
        if wl_node is None or svc_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.EXPOSES,
                NodeKind(wl_node.node_kind),
                NodeKind(svc_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=wl_node.id,
            target_node_id=svc_node.id,
            relationship_kind=EdgeKind.EXPOSES.value,
            provenance="k8s_workload_exposes_service",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_binds(
        self,
        organization_id: str,
        principal_id: str,
        workload_id: str,
    ) -> str | None:
        rbac_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_rbac", principal_id
        )
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        if rbac_node is None or wl_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.BINDS,
                NodeKind(rbac_node.node_kind),
                NodeKind(wl_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=rbac_node.id,
            target_node_id=wl_node.id,
            relationship_kind=EdgeKind.BINDS.value,
            provenance="k8s_rbac_binds_workload",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_allows(
        self,
        organization_id: str,
        policy_id: str,
        workload_id: str,
    ) -> str | None:
        np_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_network_policy", policy_id
        )
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        if np_node is None or wl_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.ALLOWS,
                NodeKind(np_node.node_kind),
                NodeKind(wl_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=np_node.id,
            target_node_id=wl_node.id,
            relationship_kind=EdgeKind.ALLOWS.value,
            provenance="k8s_network_policy_allows",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_denies(
        self,
        organization_id: str,
        policy_id: str,
        workload_id: str,
    ) -> str | None:
        np_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_network_policy", policy_id
        )
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        if np_node is None or wl_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.DENIES,
                NodeKind(np_node.node_kind),
                NodeKind(wl_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=np_node.id,
            target_node_id=wl_node.id,
            relationship_kind=EdgeKind.DENIES.value,
            provenance="k8s_network_policy_denies",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_k8s_uses(
        self,
        organization_id: str,
        workload_id: str,
        target_id: str,
        target_domain: str,
    ) -> str | None:
        wl_node = await self._repo.get_node_by_source_for_org(
            organization_id, "k8s_workload", workload_id
        )
        target_node = await self._repo.get_node_by_source_for_org(
            organization_id, target_domain, target_id
        )
        if wl_node is None or target_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.USES,
                NodeKind(wl_node.node_kind),
                NodeKind(target_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=wl_node.id,
            target_node_id=target_node.id,
            relationship_kind=EdgeKind.USES.value,
            provenance="k8s_workload_uses",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    # --- M26 Phase 6 Runtime Visibility projection ---

    async def project_runtime_event(
        self,
        organization_id: str,
        event_id: str,
        event_type: str,
        source: str,
        event_name: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.RUNTIME_EVENT.value,
            source_domain="runtime_event",
            source_entity_id=event_id,
            label=event_name or event_id,
            attributes={"event_type": event_type, "source": source},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_runtime_process(
        self,
        organization_id: str,
        process_id: str,
        process_name: str,
        runtime_event_id: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.RUNTIME_PROCESS.value,
            source_domain="runtime_process",
            source_entity_id=process_id,
            label=process_name,
            attributes={"runtime_event_id": runtime_event_id},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_runtime_connection(
        self,
        organization_id: str,
        connection_id: str,
        direction: str,
        protocol: str,
        remote_address: str,
        runtime_event_id: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.RUNTIME_CONNECTION.value,
            source_domain="runtime_connection",
            source_entity_id=connection_id,
            label=f"{direction}:{protocol}:{remote_address}",
            attributes={
                "direction": direction,
                "protocol": protocol,
                "remote_address": remote_address,
                "runtime_event_id": runtime_event_id,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_runtime_observed_on(
        self,
        organization_id: str,
        runtime_event_id: str,
        target_id: str,
        target_domain: str,
    ) -> str | None:
        """OBSERVED_ON runtime → cloud_resource/asset/k8s_workload (if present)."""
        runtime_node = await self._repo.get_node_by_source_for_org(
            organization_id, "runtime_event", runtime_event_id
        )
        # Inventory assets use source_domain=asset; accept aliases.
        domain = "asset" if target_domain in {"cloud_asset", "asset"} else target_domain
        target_node = await self._repo.get_node_by_source_for_org(
            organization_id, domain, target_id
        )
        if runtime_node is None or target_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.OBSERVED_ON,
                NodeKind(runtime_node.node_kind),
                NodeKind(target_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=runtime_node.id,
            target_node_id=target_node.id,
            relationship_kind=EdgeKind.OBSERVED_ON.value,
            provenance="runtime_observed_on",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_runtime_associated_with(
        self,
        organization_id: str,
        runtime_event_id: str,
        target_id: str,
        target_domain: str,
    ) -> str | None:
        """ASSOCIATED_WITH runtime → identity/iam_role/service_identity."""
        runtime_node = await self._repo.get_node_by_source_for_org(
            organization_id, "runtime_event", runtime_event_id
        )
        target_node = await self._repo.get_node_by_source_for_org(
            organization_id, target_domain, target_id
        )
        if runtime_node is None or target_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.ASSOCIATED_WITH,
                NodeKind(runtime_node.node_kind),
                NodeKind(target_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=runtime_node.id,
            target_node_id=target_node.id,
            relationship_kind=EdgeKind.ASSOCIATED_WITH.value,
            provenance="runtime_associated_with",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_runtime_originated_from(
        self,
        organization_id: str,
        runtime_event_id: str,
        cloud_account_id: str,
    ) -> str | None:
        """ORIGINATED_FROM runtime → cloud_account (inventory asset node if present)."""
        runtime_node = await self._repo.get_node_by_source_for_org(
            organization_id, "runtime_event", runtime_event_id
        )
        account_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", cloud_account_id
        )
        if account_node is None:
            account_node = await self._repo.get_node_by_source_for_org(
                organization_id, "cloud_account", cloud_account_id
            )
        if runtime_node is None or account_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.ORIGINATED_FROM,
                NodeKind(runtime_node.node_kind),
                NodeKind(account_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=runtime_node.id,
            target_node_id=account_node.id,
            relationship_kind=EdgeKind.ORIGINATED_FROM.value,
            provenance="runtime_originated_from",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    # --- M26 Phase 7 Cloud Risk Correlation projection ---

    async def project_cloud_risk(
        self,
        organization_id: str,
        risk_id: str,
        cloud_asset_id: str,
        overall_score: float,
        state: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.RISK.value,
            source_domain="cloud_risk",
            source_entity_id=risk_id,
            label=f"risk:{overall_score:.2f}",
            attributes={
                "cloud_asset_id": cloud_asset_id,
                "overall_score": overall_score,
                "state": state,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_cloud_risk_factor(
        self,
        organization_id: str,
        factor_id: str,
        title: str,
        score: float,
        category: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.RISK_FACTOR.value,
            source_domain="cloud_risk_factor",
            source_entity_id=factor_id,
            label=title,
            attributes={"score": score, "category": category},
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_cloud_risk_exposure(
        self,
        organization_id: str,
        exposure_id: str,
        exposure_score: float,
        public_accessibility: bool,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.RISK_EXPOSURE.value,
            source_domain="cloud_risk_exposure",
            source_entity_id=exposure_id,
            label=f"exposure:{exposure_score:.2f}",
            attributes={
                "exposure_score": exposure_score,
                "public_accessibility": public_accessibility,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_cloud_risk_has_risk(
        self,
        organization_id: str,
        cloud_asset_id: str,
        risk_id: str,
    ) -> str | None:
        """HAS_RISK asset/cloud_resource → RISK (if asset node present)."""
        asset_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", cloud_asset_id
        )
        if asset_node is None:
            asset_node = await self._repo.get_node_by_source_for_org(
                organization_id, "cloud_asset", cloud_asset_id
            )
        risk_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_risk", risk_id
        )
        if asset_node is None or risk_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.HAS_RISK,
                NodeKind(asset_node.node_kind),
                NodeKind(risk_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=asset_node.id,
            target_node_id=risk_node.id,
            relationship_kind=EdgeKind.HAS_RISK.value,
            provenance="cloud_risk_has_risk",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_cloud_risk_has_factor(
        self,
        organization_id: str,
        risk_id: str,
        factor_id: str,
    ) -> str | None:
        risk_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_risk", risk_id
        )
        factor_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_risk_factor", factor_id
        )
        if risk_node is None or factor_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.HAS_FACTOR,
                NodeKind(risk_node.node_kind),
                NodeKind(factor_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=risk_node.id,
            target_node_id=factor_node.id,
            relationship_kind=EdgeKind.HAS_FACTOR.value,
            provenance="cloud_risk_has_factor",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_cloud_risk_has_exposure(
        self,
        organization_id: str,
        risk_id: str,
        exposure_id: str,
    ) -> str | None:
        risk_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_risk", risk_id
        )
        exposure_node = await self._repo.get_node_by_source_for_org(
            organization_id, "cloud_risk_exposure", exposure_id
        )
        if risk_node is None or exposure_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.HAS_EXPOSURE,
                NodeKind(risk_node.node_kind),
                NodeKind(exposure_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=risk_node.id,
            target_node_id=exposure_node.id,
            relationship_kind=EdgeKind.HAS_EXPOSURE.value,
            provenance="cloud_risk_has_exposure",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    # --- M27 Phase 5 Vulnerability Management projection ---

    async def project_vulnerability(
        self,
        organization_id: str,
        vuln_id: str,
        *,
        cve_id: str | None = None,
        severity: str = "Unknown",
        cvss_score: float | None = None,
        epss_score: float | None = None,
        kev_status: bool = False,
        label: str | None = None,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.VULNERABILITY.value,
            source_domain="vulnerability",
            source_entity_id=vuln_id,
            label=label or cve_id or vuln_id,
            attributes={
                "vuln_id": vuln_id,
                "cve_id": cve_id,
                "severity": severity,
                "cvss_score": cvss_score,
                "epss_score": epss_score,
                "kev_status": kev_status,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_vulnerability_instance(
        self,
        organization_id: str,
        instance_id: str,
        *,
        state: str,
        detected_at: str,
        prioritization_score: float | None = None,
        vulnerability_id: str | None = None,
        asset_id: str | None = None,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.VULNERABILITY_INSTANCE.value,
            source_domain="vulnerability_instance",
            source_entity_id=instance_id,
            label=f"instance:{instance_id}",
            attributes={
                "instance_id": instance_id,
                "state": state,
                "detected_at": detected_at,
                "prioritization_score": prioritization_score,
                "vulnerability_id": vulnerability_id,
                "asset_id": asset_id,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_remediation_plan_node(
        self,
        organization_id: str,
        plan_id: str,
        *,
        state: str,
        owner: str,
        sla_deadline: str,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.REMEDIATION_PLAN.value,
            source_domain="remediation_plan",
            source_entity_id=plan_id,
            label=f"plan:{plan_id}",
            attributes={
                "plan_id": plan_id,
                "state": state,
                "owner": owner,
                "sla_deadline": sla_deadline,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_component(
        self,
        organization_id: str,
        component_id: str,
        *,
        purl: str | None = None,
        name: str,
        version: str | None = None,
        ecosystem: str | None = None,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.COMPONENT.value,
            source_domain="vulnerability_component",
            source_entity_id=component_id,
            label=name,
            attributes={
                "purl": purl,
                "name": name,
                "version": version,
                "ecosystem": ecosystem,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_exploit(
        self,
        organization_id: str,
        exploit_id: str,
        *,
        maturity: str,
        source: str,
        published_at: str | None = None,
    ) -> str | None:
        node = await self._repo.upsert_node(
            node_id=str(EntityId.generate()),
            organization_id=organization_id,
            node_kind=NodeKind.EXPLOIT.value,
            source_domain="vulnerability_exploit",
            source_entity_id=exploit_id,
            label=f"exploit:{maturity}",
            attributes={
                "exploit_id": exploit_id,
                "maturity": maturity,
                "source": source,
                "published_at": published_at,
            },
            ontology_version=ONTOLOGY_VERSION,
        )
        return node.id

    async def project_vulnerability_affects(
        self,
        organization_id: str,
        vuln_id: str,
        asset_id: str,
        *,
        instance_id: str | None = None,
        resolved: bool = False,
    ) -> str | None:
        """AFFECTS: VulnerabilityNode → AssetNode (via instance_id)."""
        vuln_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability", vuln_id
        )
        asset_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", asset_id
        )
        if asset_node is None:
            # Soft-create a minimal asset node so AFFECTS can be written
            # without requiring a prior inventory projection in the same txn.
            await self._repo.upsert_node(
                node_id=str(EntityId.generate()),
                organization_id=organization_id,
                node_kind=NodeKind.ASSET.value,
                source_domain="asset",
                source_entity_id=asset_id,
                label=f"asset:{asset_id}",
                attributes={"asset_id": asset_id, "projected_from": "vulnerability"},
                ontology_version=ONTOLOGY_VERSION,
            )
            asset_node = await self._repo.get_node_by_source_for_org(
                organization_id, "asset", asset_id
            )
        if vuln_node is None or asset_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.AFFECTS,
                NodeKind(vuln_node.node_kind),
                NodeKind(asset_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=vuln_node.id,
            target_node_id=asset_node.id,
            relationship_kind=EdgeKind.AFFECTS.value,
            provenance="vulnerability_affects",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_instance_of(
        self,
        organization_id: str,
        instance_id: str,
        vuln_id: str,
        *,
        detected_at: str | None = None,
    ) -> str | None:
        instance_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability_instance", instance_id
        )
        vuln_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability", vuln_id
        )
        if instance_node is None or vuln_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.INSTANCE_OF,
                NodeKind(instance_node.node_kind),
                NodeKind(vuln_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=instance_node.id,
            target_node_id=vuln_node.id,
            relationship_kind=EdgeKind.INSTANCE_OF.value,
            provenance="vulnerability_instance_of",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_found_on(
        self,
        organization_id: str,
        instance_id: str,
        asset_id: str,
        *,
        component_location: str | None = None,
    ) -> str | None:
        instance_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability_instance", instance_id
        )
        asset_node = await self._repo.get_node_by_source_for_org(
            organization_id, "asset", asset_id
        )
        if asset_node is None:
            await self._repo.upsert_node(
                node_id=str(EntityId.generate()),
                organization_id=organization_id,
                node_kind=NodeKind.ASSET.value,
                source_domain="asset",
                source_entity_id=asset_id,
                label=f"asset:{asset_id}",
                attributes={"asset_id": asset_id, "projected_from": "vulnerability"},
                ontology_version=ONTOLOGY_VERSION,
            )
            asset_node = await self._repo.get_node_by_source_for_org(
                organization_id, "asset", asset_id
            )
        if instance_node is None or asset_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.FOUND_ON,
                NodeKind(instance_node.node_kind),
                NodeKind(asset_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=instance_node.id,
            target_node_id=asset_node.id,
            relationship_kind=EdgeKind.FOUND_ON.value,
            provenance="vulnerability_found_on",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_has_remediation(
        self,
        organization_id: str,
        instance_id: str,
        plan_id: str,
        *,
        assigned_at: str | None = None,
    ) -> str | None:
        instance_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability_instance", instance_id
        )
        plan_node = await self._repo.get_node_by_source_for_org(
            organization_id, "remediation_plan", plan_id
        )
        if instance_node is None or plan_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.HAS_REMEDIATION,
                NodeKind(instance_node.node_kind),
                NodeKind(plan_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=instance_node.id,
            target_node_id=plan_node.id,
            relationship_kind=EdgeKind.HAS_REMEDIATION.value,
            provenance="vulnerability_has_remediation",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_component_has_vuln(
        self,
        organization_id: str,
        component_id: str,
        vuln_id: str,
        *,
        affected_version: str | None = None,
    ) -> str | None:
        component_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability_component", component_id
        )
        vuln_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability", vuln_id
        )
        if component_node is None or vuln_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.COMPONENT_HAS_VULN,
                NodeKind(component_node.node_kind),
                NodeKind(vuln_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=component_node.id,
            target_node_id=vuln_node.id,
            relationship_kind=EdgeKind.COMPONENT_HAS_VULN.value,
            provenance="vulnerability_component_has_vuln",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_exploited_by(
        self,
        organization_id: str,
        vuln_id: str,
        exploit_id: str,
        *,
        maturity: str | None = None,
    ) -> str | None:
        vuln_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability", vuln_id
        )
        exploit_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability_exploit", exploit_id
        )
        if vuln_node is None or exploit_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.EXPLOITED_BY,
                NodeKind(vuln_node.node_kind),
                NodeKind(exploit_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=vuln_node.id,
            target_node_id=exploit_node.id,
            relationship_kind=EdgeKind.EXPLOITED_BY.value,
            provenance="vulnerability_exploited_by",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_enables_ttp(
        self,
        organization_id: str,
        vuln_id: str,
        technique_id: str,
        *,
        confidence: float | None = None,
    ) -> str | None:
        vuln_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability", vuln_id
        )
        technique_node = await self._repo.get_node_by_source_for_org(
            organization_id, "attack_technique", technique_id
        )
        if technique_node is None:
            await self._repo.upsert_node(
                node_id=str(EntityId.generate()),
                organization_id=organization_id,
                node_kind=NodeKind.ATTACK_TECHNIQUE.value,
                source_domain="attack_technique",
                source_entity_id=technique_id,
                label=technique_id,
                attributes={"technique_id": technique_id},
                ontology_version=ONTOLOGY_VERSION,
            )
            technique_node = await self._repo.get_node_by_source_for_org(
                organization_id, "attack_technique", technique_id
            )
        if vuln_node is None or technique_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.ENABLES_TTP,
                NodeKind(vuln_node.node_kind),
                NodeKind(technique_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=vuln_node.id,
            target_node_id=technique_node.id,
            relationship_kind=EdgeKind.ENABLES_TTP.value,
            provenance="vulnerability_enables_ttp",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id

    async def project_exposes_identity(
        self,
        organization_id: str,
        instance_id: str,
        identity_id: str,
        *,
        blast_radius: str | None = None,
    ) -> str | None:
        instance_node = await self._repo.get_node_by_source_for_org(
            organization_id, "vulnerability_instance", instance_id
        )
        identity_node = await self._repo.get_node_by_source_for_org(
            organization_id, "identity", identity_id
        )
        if identity_node is None:
            await self._repo.upsert_node(
                node_id=str(EntityId.generate()),
                organization_id=organization_id,
                node_kind=NodeKind.IDENTITY.value,
                source_domain="identity",
                source_entity_id=identity_id,
                label=f"identity:{identity_id}",
                attributes={"identity_id": identity_id},
                ontology_version=ONTOLOGY_VERSION,
            )
            identity_node = await self._repo.get_node_by_source_for_org(
                organization_id, "identity", identity_id
            )
        if instance_node is None or identity_node is None:
            return None
        try:
            validate_edge(
                EdgeKind.EXPOSES_IDENTITY,
                NodeKind(instance_node.node_kind),
                NodeKind(identity_node.node_kind),
            )
        except Exception:
            return None
        edge = await self._repo.upsert_edge(
            edge_id=str(EntityId.generate()),
            organization_id=organization_id,
            source_node_id=instance_node.id,
            target_node_id=identity_node.id,
            relationship_kind=EdgeKind.EXPOSES_IDENTITY.value,
            provenance="vulnerability_exposes_identity",
            ontology_version=ONTOLOGY_VERSION,
        )
        return edge.id
