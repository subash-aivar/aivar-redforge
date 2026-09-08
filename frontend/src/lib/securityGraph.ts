/**
 * Security Graph API client — M4.
 *
 * Tenant-scoped throughout via the existing bearer-token session; no
 * organization_id is ever supplied client-side. There is deliberately
 * no create/update client for nodes/edges — the graph is a read-only
 * projection surface, never directly writable by the browser.
 */
import { api } from "./api";

export interface GraphNode {
  id: string;
  node_kind: string;
  label: string;
  source_domain: string;
  source_entity_id: string;
  attributes: Record<string, string>;
  ontology_version: number;
}

export interface GraphEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_kind: string;
  provenance: string;
}

export interface GraphOverview {
  nodes: GraphNode[];
  edges: GraphEdge[];
  node_count: number;
  truncated: boolean;
}

export interface NodeDetail {
  node: GraphNode;
  inbound_count: number;
  outbound_count: number;
}

export interface Neighbor {
  node: GraphNode;
  via_edge: GraphEdge;
}

export interface SecurityRelationshipPath {
  node_ids: string[];
  edge_ids: string[];
}

export async function getOverview(nodeKind?: string, limit?: number): Promise<GraphOverview> {
  const q = new URLSearchParams();
  if (nodeKind) q.set("node_kind", nodeKind);
  if (limit != null) q.set("limit", String(limit));
  const qs = q.toString();
  return api.get<GraphOverview>(`/api/v1/security-graph${qs ? `?${qs}` : ""}`);
}

export async function getNode(nodeId: string): Promise<NodeDetail> {
  return api.get<NodeDetail>(`/api/v1/security-graph/nodes/${nodeId}`);
}

export async function getNeighbors(
  nodeId: string,
  direction: "inbound" | "outbound" | "both" = "both"
): Promise<Neighbor[]> {
  return api.get<Neighbor[]>(
    `/api/v1/security-graph/nodes/${nodeId}/neighbors?direction=${direction}`
  );
}

export async function queryPaths(
  startNodeId: string,
  endNodeId: string,
  maxDepth = 4,
  relationshipKinds?: string[]
): Promise<{ paths: SecurityRelationshipPath[] }> {
  return api.post<{ paths: SecurityRelationshipPath[] }>("/api/v1/security-graph/paths/query", {
    start_node_id: startNodeId,
    end_node_id: endNodeId,
    max_depth: maxDepth,
    relationship_kinds: relationshipKinds ?? null,
  });
}
