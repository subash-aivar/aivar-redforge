import { describe, expect, it } from "vitest";
import {
  canonicalKeyOf,
  composeAttackGraph,
  filterByEdgeKind,
  filterByNodeKind,
  searchGraph,
  securityGraphEdgeToGraphEdge,
  securityGraphNodeToGraphNode,
} from "@/lib/attackGraphComposition";
import type { GraphNode as SecGraphNode, GraphEdge as SecGraphEdge } from "@/lib/securityGraph";
import type { InvestigationGraph } from "@/lib/investigations";
import type { AttackPath } from "@/lib/attackPathsApi";

function secNode(overrides: Partial<SecGraphNode> = {}): SecGraphNode {
  return {
    id: "01ULID-SURFACE",
    node_kind: "ai_agent",
    label: "Prod Agent",
    source_domain: "inventory",
    source_entity_id: "asset-1",
    attributes: {},
    ontology_version: 15,
    ...overrides,
  };
}

describe("canonicalKeyOf", () => {
  it("builds the source_domain:source_entity_id composite used by the Investigation Graph API", () => {
    expect(canonicalKeyOf("inventory", "asset-1")).toBe("inventory:asset-1");
  });
});

describe("securityGraphNodeToGraphNode", () => {
  it("uses the canonical key, not the surface ULID, as the composed node id", () => {
    const { node } = securityGraphNodeToGraphNode(secNode());
    expect(node.id).toBe("inventory:asset-1");
    expect(node.id).not.toBe("01ULID-SURFACE");
  });
});

describe("securityGraphEdgeToGraphEdge", () => {
  it("remaps surface node ids to canonical ids via the supplied lookup", () => {
    const map = new Map([
      ["surface-a", "inventory:asset-1"],
      ["surface-b", "inventory:asset-2"],
    ]);
    const edge: SecGraphEdge = {
      id: "e1",
      source_node_id: "surface-a",
      target_node_id: "surface-b",
      relationship_kind: "connects_to",
      provenance: "discovery",
    };
    const result = securityGraphEdgeToGraphEdge(edge, map);
    expect(result).toEqual({ id: "sg:e1", source: "inventory:asset-1", target: "inventory:asset-2", label: "connects_to" });
  });

  it("drops edges whose endpoint is not in the supplied node set rather than leaving a dangling reference", () => {
    const map = new Map([["surface-a", "inventory:asset-1"]]);
    const edge: SecGraphEdge = {
      id: "e1",
      source_node_id: "surface-a",
      target_node_id: "surface-missing",
      relationship_kind: "connects_to",
      provenance: "discovery",
    };
    expect(securityGraphEdgeToGraphEdge(edge, map)).toBeNull();
  });
});

describe("composeAttackGraph", () => {
  const securityGraph = {
    nodes: [secNode({ id: "surface-1", source_domain: "inventory", source_entity_id: "asset-1" })],
    edges: [] as SecGraphEdge[],
  };

  const investigationGraph: InvestigationGraph = {
    case_id: "case-1",
    ontology_version: 6,
    nodes: [
      { id: "inventory:asset-1", kind: "ai_agent", label: "Prod Agent", severity: "HIGH", status: "active", source_domain: "inventory" },
      { id: "inventory:asset-2", kind: "finding", label: "Exposed Key", severity: "CRITICAL" },
    ],
    edges: [{ source: "inventory:asset-1", target: "inventory:asset-2", kind: "correlated_with", observability: "direct", reason: "same evidence" }],
  };

  const attackPath: AttackPath = {
    id: "ap-1",
    organization_id: "org-1",
    root_entity_id: "fused-1",
    root_canonical_key: "indicator:fused-1",
    terminal_entity_id: "fused-2",
    path_confidence: "high",
    technique_coverage: [],
    attributed_actors: [],
    step_count: 2,
    evidence_count: 3,
    max_exposure_score: 0.9,
    status: "active",
    steps: [
      { sequence: 0, entity_id: "fused-1", canonical_key: "indicator:fused-1", step_type: "initial_access", confidence: "high", technique_id: "T1190", evidence_refs: [], relationship_type: null, kill_chain_phase: "initial-access", inferred_from_step: null, exposure_score: 0.5 },
      { sequence: 1, entity_id: "fused-2", canonical_key: "indicator:fused-2", step_type: "lateral_movement", confidence: "medium", technique_id: "T1021", evidence_refs: [], relationship_type: "enables", kill_chain_phase: "lateral-movement", inferred_from_step: 0, exposure_score: 0.7 },
    ],
    alternate_path_count: 0,
    investigation_id: null,
  };

  it("merges a Security Graph node and an Investigation Graph node that share a canonical key into one node", () => {
    const { model } = composeAttackGraph({
      securityGraph,
      investigationGraph,
      attackPaths: null,
      activeLayers: new Set(["security-graph", "investigation"]),
    });
    const merged = model.nodes.filter((n) => n.id === "inventory:asset-1");
    expect(merged).toHaveLength(1);
    // node not present in the security graph but present in the investigation graph is still added
    expect(model.nodes.some((n) => n.id === "inventory:asset-2")).toBe(true);
  });

  it("never merges Attack Path steps into the Security/Investigation node set — they stay a separate ap: layer", () => {
    const { model, meta } = composeAttackGraph({
      securityGraph,
      investigationGraph,
      attackPaths: [attackPath],
      activeLayers: new Set(["security-graph", "investigation", "attack-path"]),
    });
    const apNodes = model.nodes.filter((n) => n.id.startsWith("ap:"));
    expect(apNodes).toHaveLength(2);
    expect(apNodes.every((n) => meta[n.id].layer === "attack-path")).toBe(true);
    // no collision with canonical-key-space node ids
    expect(model.nodes.some((n) => n.id === "fused-1" || n.id === "fused-2")).toBe(false);
  });

  it("only includes layers present in activeLayers", () => {
    const { model } = composeAttackGraph({
      securityGraph,
      investigationGraph,
      attackPaths: [attackPath],
      activeLayers: new Set(["security-graph"]),
    });
    expect(model.nodes).toHaveLength(1);
    expect(model.nodes[0].id).toBe("inventory:asset-1");
  });

  it("chains attack-path edges sequentially between consecutive steps", () => {
    const { model } = composeAttackGraph({
      securityGraph: null,
      investigationGraph: null,
      attackPaths: [attackPath],
      activeLayers: new Set(["attack-path"]),
    });
    expect(model.edges).toHaveLength(1);
    expect(model.edges[0].source).toBe("ap:ap-1:0:fused-1");
    expect(model.edges[0].target).toBe("ap:ap-1:1:fused-2");
  });
});

describe("searchGraph", () => {
  it("filters nodes by label or id substring, and drops edges with a filtered-out endpoint", () => {
    const model = {
      nodes: [
        { id: "a", label: "Prod Agent", kind: "ai_agent" },
        { id: "b", label: "Exposed Key", kind: "finding" },
      ],
      edges: [{ id: "e1", source: "a", target: "b" }],
    };
    const result = searchGraph(model, "prod");
    expect(result.nodes).toEqual([{ id: "a", label: "Prod Agent", kind: "ai_agent" }]);
    expect(result.edges).toHaveLength(0);
  });

  it("returns the model unchanged for an empty query", () => {
    const model = { nodes: [{ id: "a", label: "A", kind: "k" }], edges: [] };
    expect(searchGraph(model, "  ")).toBe(model);
  });
});

describe("filterByNodeKind", () => {
  it("keeps only nodes whose real rawKind is in the selected set, using meta not a hardcoded enum", () => {
    const model = {
      nodes: [
        { id: "a", label: "A", kind: "ai_agent" },
        { id: "b", label: "B", kind: "finding" },
      ],
      edges: [{ id: "e1", source: "a", target: "b" }],
    };
    const meta = {
      a: { layer: "security-graph" as const, rawKind: "ai_agent" },
      b: { layer: "security-graph" as const, rawKind: "finding" },
    };
    const result = filterByNodeKind(model, meta, new Set(["finding"]));
    expect(result.nodes.map((n) => n.id)).toEqual(["b"]);
    expect(result.edges).toHaveLength(0);
  });
});

describe("filterByEdgeKind", () => {
  it("keeps only edges with a matching label and prunes orphaned nodes", () => {
    const model = {
      nodes: [
        { id: "a", label: "A", kind: "k" },
        { id: "b", label: "B", kind: "k" },
        { id: "c", label: "C", kind: "k" },
      ],
      edges: [
        { id: "e1", source: "a", target: "b", label: "connects_to" },
        { id: "e2", source: "a", target: "c", label: "correlated_with" },
      ],
    };
    const result = filterByEdgeKind(model, new Set(["connects_to"]));
    expect(result.edges).toHaveLength(1);
    expect(result.nodes.map((n) => n.id).sort()).toEqual(["a", "b"]);
  });
});
