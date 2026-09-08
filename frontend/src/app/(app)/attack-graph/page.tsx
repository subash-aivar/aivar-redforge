"use client";

import { useEffect, useMemo, useState } from "react";
import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { LoadingState, ErrorState, EmptyState } from "@/design-system/primitives/States";
import { GraphWidget } from "@/components/dashboard/widgets/GraphWidget";
import { getOrganizationId } from "@/lib/api";
import {
  getOverview,
  getNode,
  getNeighbors,
  type GraphOverview,
  type NodeDetail,
  type Neighbor,
} from "@/lib/securityGraph";
import {
  getInvestigationGraph,
  listInvestigations,
  type InvestigationGraph,
  type InvestigationCase,
} from "@/lib/investigations";
import { listAttackPaths, type AttackPath } from "@/lib/attackPathsApi";
import {
  composeAttackGraph,
  searchGraph,
  filterByNodeKind,
  filterByEdgeKind,
  type LayerId,
} from "@/lib/attackGraphComposition";

const OVERVIEW_LIMIT = 250;

const LAYER_LABELS: Record<LayerId, string> = {
  "security-graph": "Security Graph",
  investigation: "Investigation Graph",
  "attack-path": "Attack Paths",
};

/**
 * Enterprise Attack Graph Explorer.
 *
 * Composes the Security Graph, one Investigation Graph, and the current
 * organization's Attack Paths into one visual graph via
 * `@/lib/attackGraphComposition`'s `composeAttackGraph` — see that
 * module's header for the join-key audit. Security Graph and
 * Investigation Graph nodes for the same entity are merged onto the
 * shared `source_domain:source_entity_id` canonical key; Attack Path
 * steps are threat-intel fusion-indicator identifiers with no verified
 * mapping back to that key, so they render as an independent `ap:`
 * namespaced layer, never coalesced with the other two.
 */
export default function AttackGraphExplorerPage() {
  const [activeLayers, setActiveLayers] = useState<Set<LayerId>>(
    new Set<LayerId>(["security-graph", "investigation"]),
  );

  const [overview, setOverview] = useState<GraphOverview | null>(null);
  const [sgError, setSgError] = useState("");

  const [cases, setCases] = useState<InvestigationCase[] | null>(null);
  const [selectedCaseId, setSelectedCaseId] = useState<string>("");
  const [invGraph, setInvGraph] = useState<InvestigationGraph | null>(null);
  const [invError, setInvError] = useState("");
  // Distinct from `invError` — a fresh org with zero investigation cases
  // is an honest, expected state, not a failure. Rendering it through
  // `ErrorState` (red banner) previously conflated the two.
  const [invEmpty, setInvEmpty] = useState("");

  const [attackPaths, setAttackPaths] = useState<AttackPath[] | null>(null);
  const [apError, setApError] = useState("");

  const [search, setSearch] = useState("");
  const [nodeKindFilter, setNodeKindFilter] = useState<Set<string>>(new Set());
  const [edgeKindFilter, setEdgeKindFilter] = useState<Set<string>>(new Set());

  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [nodeDetail, setNodeDetail] = useState<NodeDetail | null>(null);
  const [nodeNeighbors, setNodeNeighbors] = useState<Neighbor[] | null>(null);
  const [drawerError, setDrawerError] = useState("");

  const orgId = getOrganizationId();

  useEffect(() => {
    if (!activeLayers.has("security-graph")) return;
    setOverview(null);
    setSgError("");
    getOverview(undefined, OVERVIEW_LIMIT)
      .then(setOverview)
      .catch(() => setSgError("UNAVAILABLE — failed to load the Security Graph."));
    // Intentionally keyed only on layer membership, not on every state
    // change, so toggling other layers doesn't refetch this one.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLayers.has("security-graph")]);

  useEffect(() => {
    if (!activeLayers.has("investigation")) return;
    if (cases === null) {
      listInvestigations({ limit: 50 })
        .then((list) => {
          setCases(list);
          if (list.length > 0 && !selectedCaseId) setSelectedCaseId(list[0].id);
          if (list.length === 0) setInvEmpty("No investigations available for this organization.");
        })
        .catch(() => setInvError("UNAVAILABLE — failed to load investigations."));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLayers.has("investigation"), cases, selectedCaseId]);

  useEffect(() => {
    if (!activeLayers.has("investigation") || !selectedCaseId) return;
    setInvGraph(null);
    setInvError("");
    setInvEmpty("");
    getInvestigationGraph(selectedCaseId)
      .then(setInvGraph)
      .catch(() => setInvError("UNAVAILABLE — failed to load the investigation graph."));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLayers.has("investigation"), selectedCaseId]);

  useEffect(() => {
    if (!activeLayers.has("attack-path")) return;
    if (!orgId) {
      setApError("No organization selected — attack paths are organization-scoped.");
      return;
    }
    setAttackPaths(null);
    setApError("");
    listAttackPaths({ organization_id: orgId, limit: 50 })
      .then(setAttackPaths)
      .catch(() => setApError("UNAVAILABLE — failed to load attack paths."));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeLayers.has("attack-path"), orgId]);

  const composed = useMemo(
    () =>
      composeAttackGraph({
        securityGraph: overview ? { nodes: overview.nodes, edges: overview.edges } : null,
        investigationGraph: invGraph,
        attackPaths,
        activeLayers,
      }),
    [overview, invGraph, attackPaths, activeLayers],
  );

  const filteredModel = useMemo(() => {
    let m = searchGraph(composed.model, search);
    m = filterByNodeKind(m, composed.meta, nodeKindFilter);
    m = filterByEdgeKind(m, edgeKindFilter);
    return m;
  }, [composed, search, nodeKindFilter, edgeKindFilter]);

  const availableNodeKinds = useMemo(
    () => Array.from(new Set(composed.model.nodes.map((n) => composed.meta[n.id]?.rawKind ?? n.kind))).sort(),
    [composed],
  );
  const availableEdgeKinds = useMemo(
    () =>
      Array.from(
        new Set(composed.model.edges.map((e) => e.label).filter((l): l is string => !!l)),
      ).sort(),
    [composed],
  );

  const anyLoading =
    (activeLayers.has("security-graph") && overview === null && !sgError) ||
    (activeLayers.has("investigation") && invGraph === null && !invError && !!selectedCaseId) ||
    (activeLayers.has("attack-path") && attackPaths === null && !apError);

  function toggleLayer(layer: LayerId) {
    const next = new Set(activeLayers);
    if (next.has(layer)) next.delete(layer);
    else next.add(layer);
    setActiveLayers(next);
    closeDrawer();
  }

  function toggleInSet(set: Set<string>, value: string, setter: (s: Set<string>) => void) {
    const next = new Set(set);
    if (next.has(value)) next.delete(value);
    else next.add(value);
    setter(next);
  }

  function resetFilters() {
    setSearch("");
    setNodeKindFilter(new Set());
    setEdgeKindFilter(new Set());
  }

  function closeDrawer() {
    setSelectedNodeId(null);
    setNodeDetail(null);
    setNodeNeighbors(null);
    setDrawerError("");
  }

  async function onNodeClick(nodeId: string) {
    setSelectedNodeId(nodeId);
    setNodeDetail(null);
    setNodeNeighbors(null);
    setDrawerError("");

    const meta = composed.meta[nodeId];
    if (meta?.layer !== "security-graph" && meta?.layer !== "investigation") {
      // Attack Path step — no dedicated node-lookup endpoint exists;
      // the composed model itself already carries every real field
      // (label/kind/severity), rendered in the fallback panel below.
      return;
    }

    // Pivot into the real Security Graph API: canonical key ->
    // surface node id lookup, via the overview payload already loaded.
    const surfaceNode = overview?.nodes.find(
      (n) => `${n.source_domain}:${n.source_entity_id}` === nodeId,
    );
    if (!surfaceNode) {
      // Investigation-only entity — no matching Security Graph node
      // was projected for it, so there is no /neighbors call to make.
      return;
    }
    try {
      const [detail, neighbors] = await Promise.all([
        getNode(surfaceNode.id),
        getNeighbors(surfaceNode.id),
      ]);
      setNodeDetail(detail);
      setNodeNeighbors(neighbors);
    } catch {
      setDrawerError("UNAVAILABLE — failed to load node detail.");
    }
  }

  async function pivotToNeighbor(neighborSurfaceId: string) {
    const target = overview?.nodes.find((n) => n.id === neighborSurfaceId);
    if (!target) return;
    await onNodeClick(`${target.source_domain}:${target.source_entity_id}`);
  }

  const selectedComposedNode = selectedNodeId
    ? composed.model.nodes.find((n) => n.id === selectedNodeId) ?? null
    : null;
  const selectedMeta = selectedNodeId ? composed.meta[selectedNodeId] : undefined;

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Attack Graph Explorer</h1>
      <p className="mt-1 text-sm text-gray-400">
        Composes the Security Graph and one Investigation Graph on their shared
        canonical key (source_domain:source_entity_id), with Attack Path results
        layered on top as an independent graph — Attack Path entities are
        threat-intel indicator identifiers with no verified join back to the
        Security Graph, so they are never merged into the same node id-space.
      </p>

      <div className="mt-4 flex flex-wrap gap-2">
        {(Object.keys(LAYER_LABELS) as LayerId[]).map((l) => (
          <button
            key={l}
            onClick={() => toggleLayer(l)}
            className={`rounded-lg px-3 py-1.5 text-sm font-medium ${
              activeLayers.has(l)
                ? "bg-blue-600 text-white"
                : "border border-gray-700 bg-gray-800 text-gray-300 hover:bg-gray-700"
            }`}
          >
            {LAYER_LABELS[l]}
          </button>
        ))}
      </div>

      {activeLayers.has("investigation") && (
        <div className="mt-3 flex items-center gap-2">
          <label className="text-xs text-gray-500">Investigation case</label>
          <select
            value={selectedCaseId}
            onChange={(e) => setSelectedCaseId(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
          >
            {(cases ?? []).map((c) => (
              <option key={c.id} value={c.id}>
                {c.title}
              </option>
            ))}
          </select>
        </div>
      )}

      <Card className="mt-4">
        <div className="flex flex-wrap items-end gap-4">
          <div>
            <label className="block text-xs text-gray-500">Search (label / id)</label>
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter nodes…"
              className="mt-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white placeholder-gray-500"
            />
          </div>
          {availableNodeKinds.length > 0 && (
            <div>
              <label className="block text-xs text-gray-500">Node kind</label>
              <div className="mt-1 flex flex-wrap gap-1">
                {availableNodeKinds.map((k) => (
                  <button
                    key={k}
                    onClick={() => toggleInSet(nodeKindFilter, k, setNodeKindFilter)}
                    className={`rounded border px-2 py-0.5 font-mono text-xs ${
                      nodeKindFilter.has(k)
                        ? "border-blue-600 bg-blue-950 text-blue-300"
                        : "border-gray-700 bg-gray-800 text-gray-400"
                    }`}
                  >
                    {k}
                  </button>
                ))}
              </div>
            </div>
          )}
          {availableEdgeKinds.length > 0 && (
            <div>
              <label className="block text-xs text-gray-500">Edge kind</label>
              <div className="mt-1 flex flex-wrap gap-1">
                {availableEdgeKinds.map((k) => (
                  <button
                    key={k}
                    onClick={() => toggleInSet(edgeKindFilter, k, setEdgeKindFilter)}
                    className={`rounded border px-2 py-0.5 font-mono text-xs ${
                      edgeKindFilter.has(k)
                        ? "border-purple-600 bg-purple-950 text-purple-300"
                        : "border-gray-700 bg-gray-800 text-gray-400"
                    }`}
                  >
                    {k}
                  </button>
                ))}
              </div>
            </div>
          )}
          {(search || nodeKindFilter.size > 0 || edgeKindFilter.size > 0) && (
            <button onClick={resetFilters} className="text-xs text-gray-500 hover:text-gray-300">
              Clear filters
            </button>
          )}
        </div>
      </Card>

      <div className="mt-4">
        {sgError && <ErrorState message={sgError} />}
        {invError && <ErrorState message={invError} />}
        {invEmpty && <EmptyState message={invEmpty} />}
        {apError && <ErrorState message={apError} />}
        {activeLayers.size === 0 && <EmptyState message="Select at least one layer to explore." />}
        {anyLoading && activeLayers.size > 0 && <LoadingState label="Loading graph…" />}

        {activeLayers.size > 0 && !anyLoading && (
          <GraphWidget
            id="attack-graph-explorer"
            title="Composed Attack Graph"
            model={filteredModel}
            onNodeClick={onNodeClick}
            height={560}
            emptyMessage="No nodes match the current layers/filters."
          />
        )}

        {activeLayers.has("security-graph") && overview?.truncated && (
          <p className="mt-2 text-xs text-yellow-500">
            Security Graph result truncated at {OVERVIEW_LIMIT} nodes — narrow with search/kind
            filters to see more.
          </p>
        )}
      </div>

      {selectedNodeId && selectedComposedNode && (
        <Card className="mt-4">
          <div className="flex items-center justify-between">
            <SectionHeader title="Entity Detail" />
            <button onClick={closeDrawer} className="text-xs text-gray-500 hover:text-gray-300">
              Close
            </button>
          </div>

          {drawerError && <div className="mt-3 text-sm text-red-400">{drawerError}</div>}

          {!drawerError && nodeDetail && (
            <div className="mt-3">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Stat label="Kind" value={nodeDetail.node.node_kind} />
                <Stat label="Source" value={nodeDetail.node.source_domain} />
                <Stat label="Inbound" value={String(nodeDetail.inbound_count)} />
                <Stat label="Outbound" value={String(nodeDetail.outbound_count)} />
              </div>
              <div className="mt-4">
                <div className="mb-2 text-sm font-medium text-gray-400">
                  Relationships ({nodeNeighbors?.length ?? 0}) — click to pivot
                </div>
                {nodeNeighbors === null ? (
                  <div className="text-xs text-gray-500">Loading…</div>
                ) : nodeNeighbors.length === 0 ? (
                  <div className="text-xs text-gray-600">No relationships recorded.</div>
                ) : (
                  <div className="space-y-2">
                    {nodeNeighbors.map((nb) => (
                      <button
                        key={nb.via_edge.id}
                        onClick={() => pivotToNeighbor(nb.node.id)}
                        className="block w-full rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-left text-xs hover:border-blue-700"
                      >
                        <span className="font-mono text-blue-400">{nb.via_edge.relationship_kind}</span>
                        <span className="text-gray-600"> → </span>
                        <span className="text-gray-300">{nb.node.label}</span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {!drawerError && !nodeDetail && (
            <div className="mt-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Stat label="Label" value={selectedComposedNode.label} />
              <Stat label="Kind" value={selectedMeta?.rawKind ?? selectedComposedNode.kind} />
              <Stat label="Layer" value={LAYER_LABELS[selectedMeta?.layer ?? "security-graph"]} />
              <Stat label="Status" value={selectedMeta?.status ?? "—"} />
              {selectedMeta?.sourceDomain && <Stat label="Source domain" value={selectedMeta.sourceDomain} />}
              <Stat label="Composed id" value={selectedComposedNode.id} />
            </div>
          )}
        </Card>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="truncate text-sm font-bold text-white">{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}
