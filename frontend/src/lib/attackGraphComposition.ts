/**
 * Attack Graph Explorer — composition layer (M-flagship).
 *
 * Composes three independently-sourced graphs into one renderer-agnostic
 * `GraphModel` (see `@/components/dashboard/graph/graphTypes`):
 *
 *   1. Security Graph        — canonical asset projection (`/api/v1/security-graph`)
 *   2. Investigation Graph   — cross-domain correlation graph for one case
 *                              (`/api/v1/investigations/{id}/graph`)
 *   3. Attack Path layer     — fusion-derived exploitability chain
 *                              (`/api/v1/attack-paths`)
 *
 * JOIN-KEY AUDIT (required before any merge):
 * Security Graph nodes have a surface `id` (a ULID primary key — see
 * `SecurityGraphNodeModel.id` in
 * `backend/src/redforge/infrastructure/database/models/security_graph.py`)
 * that is NOT the canonical identity. The model's own docstring is
 * explicit: "Canonical identity is NOT the primary key column — it's
 * the unique constraint on (organization_id, source_domain,
 * source_entity_id)".
 *
 * Investigation Graph nodes (`GET /investigations/{id}/graph`) are built
 * server-side in `backend/src/redforge/api/v1/investigations.py`
 * (`get_investigation_graph`) with
 * `entity_node_id = f"{link.source_domain}:{link.source_entity_id}"` —
 * i.e. the Investigation Graph node `id` IS the composite
 * `source_domain:source_entity_id` canonical key.
 *
 * So a Security Graph node's surface `id` (ULID) never equals an
 * Investigation Graph node's `id` (composite string) directly — merging
 * on raw `id` would silently produce zero matches. The real join key is
 * `${source_domain}:${source_entity_id}`, computable on the Security
 * Graph side from its `source_domain`/`source_entity_id` fields and
 * already the Investigation Graph node's `id`. This module joins on that
 * computed key, not on `GraphNode.id` equality.
 *
 * Attack Path steps (`AttackStep.entity_id` / `canonical_key`), however,
 * are built from `redforge.domain.threat_intel.fusion_entity.FusedIndicator`
 * (see `backend/src/redforge/domain/attack_path/graph.py` and
 * `attack_path_service.py`) — an entirely different identity space
 * (threat-intel fusion indicators, not canonical assets). There is no
 * documented or code-enforced mapping from a `FusedIndicator` id back to
 * a `SecurityGraphNodeModel.source_entity_id`. Forcing a merge on string
 * equality would silently coalesce unrelated entities the moment two
 * identity spaces happened to produce the same string.
 *
 * Decision: Attack Path results are rendered as an independent,
 * toggleable LAYER with their own node/edge ids (prefixed `ap:`), never
 * merged into the Security/Investigation node set. This is the honest
 * composition given the verified absence of a join key.
 */
import type { GraphModel, GraphNode, GraphEdge } from "@/components/dashboard/graph/graphTypes";
import type { GraphNode as SecGraphNode, GraphEdge as SecGraphEdge } from "@/lib/securityGraph";
import type { InvestigationGraph } from "@/lib/investigations";
import type { AttackPath } from "@/lib/attackPathsApi";
import type { Severity } from "@/design-system/tokens";

export type LayerId = "security-graph" | "investigation" | "attack-path";

export interface ComposedNodeMeta {
  layer: LayerId;
  rawKind: string;
  sourceDomain?: string;
  status?: string;
}

/** Extra, renderer-agnostic metadata kept alongside each `GraphNode` so
 * the drawer can show real fields without re-fetching. Keyed by node id. */
export type NodeMetaIndex = Record<string, ComposedNodeMeta>;

const INVESTIGATION_SEVERITY: Record<string, Severity> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
};

function confidenceToSeverity(confidence: string): Severity | undefined {
  switch (confidence.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "very_low":
      return "informational";
    default:
      return undefined;
  }
}

/** The canonical join key shared by Security Graph and Investigation
 * Graph nodes — see the module-level join-key audit. */
export function canonicalKeyOf(sourceDomain: string, sourceEntityId: string): string {
  return `${sourceDomain}:${sourceEntityId}`;
}

/** Security Graph node -> composed `GraphNode`. Uses the *canonical*
 * key (`source_domain:source_entity_id`) as the composed graph id
 * rather than the surface ULID `id`, so an Investigation Graph node for
 * the same entity merges onto it instead of duplicating it. */
export function securityGraphNodeToGraphNode(n: SecGraphNode): { node: GraphNode; meta: ComposedNodeMeta } {
  const canonicalId = canonicalKeyOf(n.source_domain, n.source_entity_id);
  return {
    node: { id: canonicalId, label: n.label, kind: n.node_kind },
    meta: { layer: "security-graph", rawKind: n.node_kind, sourceDomain: n.source_domain },
  };
}

/** Security Graph edges reference nodes by surface ULID id
 * (`source_node_id`/`target_node_id`), not the canonical key used for
 * composed node ids — `surfaceIdToCanonical` (built from the same node
 * list) remaps them. Edges whose endpoint isn't in the supplied node
 * list are dropped rather than left dangling. */
export function securityGraphEdgeToGraphEdge(
  e: SecGraphEdge,
  surfaceIdToCanonical: Map<string, string>
): GraphEdge | null {
  const source = surfaceIdToCanonical.get(e.source_node_id);
  const target = surfaceIdToCanonical.get(e.target_node_id);
  if (!source || !target) return null;
  return {
    id: `sg:${e.id}`,
    source,
    target,
    label: e.relationship_kind,
  };
}

export function investigationGraphToLayer(
  graph: InvestigationGraph,
  existingIds: Set<string>
): { nodes: GraphNode[]; edges: GraphEdge[]; meta: NodeMetaIndex } {
  const meta: NodeMetaIndex = {};
  const nodes: GraphNode[] = [];
  for (const n of graph.nodes) {
    if (existingIds.has(n.id)) {
      // Same canonical identity as an already-present Security Graph
      // node — merge by not re-adding it, but keep the richer
      // investigation-supplied severity/status in the meta index.
      meta[n.id] = {
        layer: "investigation",
        rawKind: n.kind,
        sourceDomain: n.source_domain,
        status: n.status,
      };
      continue;
    }
    existingIds.add(n.id);
    nodes.push({
      id: n.id,
      label: n.label,
      kind: n.kind,
      severity: n.severity ? INVESTIGATION_SEVERITY[n.severity.toUpperCase()] : undefined,
    });
    meta[n.id] = {
      layer: "investigation",
      rawKind: n.kind,
      sourceDomain: n.source_domain,
      status: n.status,
    };
  }
  const edges: GraphEdge[] = graph.edges.map((e, i) => ({
    id: `inv:${graph.case_id}:${i}:${e.source}:${e.target}`,
    source: e.source,
    target: e.target,
    label: e.kind,
  }));
  return { nodes, edges, meta };
}

/** Attack Path rendered as an isolated layer — node ids are namespaced
 * `ap:` and never coalesced with Security/Investigation node ids (see
 * module-level join-key audit above). */
export function attackPathToLayer(path: AttackPath): { nodes: GraphNode[]; edges: GraphEdge[]; meta: NodeMetaIndex } {
  const meta: NodeMetaIndex = {};
  const steps = path.steps ?? [];
  const nodes: GraphNode[] = steps.map((s) => {
    const id = `ap:${path.id}:${s.sequence}:${s.entity_id}`;
    meta[id] = { layer: "attack-path", rawKind: s.step_type };
    return {
      id,
      label: s.technique_id ? `${s.step_type} (${s.technique_id})` : s.step_type,
      kind: s.step_type,
      severity: confidenceToSeverity(s.confidence),
    };
  });
  const edges: GraphEdge[] = [];
  for (let i = 1; i < steps.length; i++) {
    const prev = steps[i - 1];
    const cur = steps[i];
    edges.push({
      id: `ap:${path.id}:edge:${prev.sequence}-${cur.sequence}`,
      source: `ap:${path.id}:${prev.sequence}:${prev.entity_id}`,
      target: `ap:${path.id}:${cur.sequence}:${cur.entity_id}`,
      label: cur.relationship_type ?? undefined,
    });
  }
  return { nodes, edges, meta };
}

export interface ComposeInput {
  securityGraph?: { nodes: SecGraphNode[]; edges: SecGraphEdge[] } | null;
  investigationGraph?: InvestigationGraph | null;
  attackPaths?: AttackPath[] | null;
  activeLayers: Set<LayerId>;
}

export interface ComposeResult {
  model: GraphModel;
  meta: NodeMetaIndex;
}

/** Pure composition function — no I/O, no fetching. Deterministic given
 * its inputs, so it is unit-testable without a backend. */
export function composeAttackGraph(input: ComposeInput): ComposeResult {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const meta: NodeMetaIndex = {};
  const seenIds = new Set<string>();

  if (input.activeLayers.has("security-graph") && input.securityGraph) {
    const surfaceIdToCanonical = new Map<string, string>();
    for (const n of input.securityGraph.nodes) {
      surfaceIdToCanonical.set(n.id, canonicalKeyOf(n.source_domain, n.source_entity_id));
    }
    for (const n of input.securityGraph.nodes) {
      const { node, meta: m } = securityGraphNodeToGraphNode(n);
      if (seenIds.has(node.id)) continue;
      seenIds.add(node.id);
      nodes.push(node);
      meta[node.id] = m;
    }
    for (const e of input.securityGraph.edges) {
      const edge = securityGraphEdgeToGraphEdge(e, surfaceIdToCanonical);
      if (edge !== null) edges.push(edge);
    }
  }

  if (input.activeLayers.has("investigation") && input.investigationGraph) {
    const layer = investigationGraphToLayer(input.investigationGraph, seenIds);
    nodes.push(...layer.nodes);
    edges.push(...layer.edges);
    Object.assign(meta, layer.meta);
  }

  if (input.activeLayers.has("attack-path") && input.attackPaths) {
    for (const p of input.attackPaths) {
      const layer = attackPathToLayer(p);
      nodes.push(...layer.nodes);
      edges.push(...layer.edges);
      Object.assign(meta, layer.meta);
    }
  }

  return { model: { nodes, edges }, meta };
}

/** Client-side search: label or id substring, case-insensitive. */
export function searchGraph(model: GraphModel, query: string): GraphModel {
  if (!query.trim()) return model;
  const q = query.trim().toLowerCase();
  const matchedIds = new Set(
    model.nodes.filter((n) => n.label.toLowerCase().includes(q) || n.id.toLowerCase().includes(q)).map((n) => n.id)
  );
  return {
    nodes: model.nodes.filter((n) => matchedIds.has(n.id)),
    edges: model.edges.filter((e) => matchedIds.has(e.source) && matchedIds.has(e.target)),
  };
}

/** Client-side node-kind filter — kind set is derived from the data
 * itself (real `rawKind` values seen), never hardcoded. */
export function filterByNodeKind(model: GraphModel, meta: NodeMetaIndex, kinds: Set<string>): GraphModel {
  if (kinds.size === 0) return model;
  const keep = new Set(model.nodes.filter((n) => kinds.has(meta[n.id]?.rawKind ?? n.kind)).map((n) => n.id));
  return {
    nodes: model.nodes.filter((n) => keep.has(n.id)),
    edges: model.edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
  };
}

/** Client-side edge-kind (relationship label) filter. */
export function filterByEdgeKind(model: GraphModel, kinds: Set<string>): GraphModel {
  if (kinds.size === 0) return model;
  const edges = model.edges.filter((e) => e.label && kinds.has(e.label));
  const keepNodeIds = new Set<string>();
  for (const e of edges) {
    keepNodeIds.add(e.source);
    keepNodeIds.add(e.target);
  }
  return {
    nodes: model.nodes.filter((n) => keepNodeIds.has(n.id)),
    edges,
  };
}
