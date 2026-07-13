"use client";

import { useEffect, useState } from "react";
import {
  getNeighbors,
  getNode,
  getOverview,
  queryPaths,
  type GraphEdge,
  type GraphNode,
  type Neighbor,
  type NodeDetail,
  type SecurityRelationshipPath,
} from "@/lib/securityGraph";

const KNOWN_NODE_KINDS = new Set([
  "asset", "application", "ai_system", "ai_agent", "model", "host",
  "ip_address", "cloud_resource", "data_store", "finding",
]);

function canonicalKind(kind: string): string {
  return KNOWN_NODE_KINDS.has(kind) ? kind : "UNKNOWN";
}

export default function SecurityGraphPage() {
  const [nodes, setNodes] = useState<GraphNode[] | null>(null);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [error, setError] = useState("");
  const [nodeKindFilter, setNodeKindFilter] = useState("");

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<NodeDetail | null>(null);
  const [neighbors, setNeighbors] = useState<Neighbor[] | null>(null);
  const [detailError, setDetailError] = useState("");

  const [startNodeId, setStartNodeId] = useState("");
  const [endNodeId, setEndNodeId] = useState("");
  const [paths, setPaths] = useState<SecurityRelationshipPath[] | null>(null);
  const [pathError, setPathError] = useState("");
  const [pathLoading, setPathLoading] = useState(false);

  function load() {
    getOverview(nodeKindFilter || undefined)
      .then((o) => {
        setNodes(o.nodes);
        setEdges(o.edges);
      })
      .catch(() => setError("UNAVAILABLE — failed to load the Security Graph."));
  }

  useEffect(load, [nodeKindFilter]);

  async function openDetail(id: string) {
    setSelectedId(id);
    setDetail(null);
    setNeighbors(null);
    setDetailError("");
    try {
      const [d, n] = await Promise.all([getNode(id), getNeighbors(id)]);
      setDetail(d);
      setNeighbors(n);
    } catch {
      setDetailError("UNAVAILABLE — failed to load node detail.");
    }
  }

  async function runPathQuery() {
    setPathLoading(true);
    setPathError("");
    setPaths(null);
    try {
      const result = await queryPaths(startNodeId, endNodeId, 4);
      setPaths(result.paths);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Path query failed";
      setPathError(msg);
    } finally {
      setPathLoading(false);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Security Graph</h1>
      <p className="mt-1 text-sm text-gray-400">
        Tenant-scoped projection of security-relevant nodes and relationships,
        derived from canonical assets — not a source of truth, not an attack
        graph.
      </p>

      <div className="mt-4 flex items-center gap-2">
        <label className="text-xs text-gray-500">Node kind filter</label>
        <input
          value={nodeKindFilter}
          onChange={(e) => setNodeKindFilter(e.target.value)}
          placeholder="e.g. ai_agent"
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white placeholder-gray-500"
        />
      </div>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : nodes === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : nodes.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No graph nodes yet. Create an AI target or run connector discovery —
          canonical assets project into the graph automatically.
        </div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Label</th>
                <th className="px-4 py-2">Kind</th>
                <th className="px-4 py-2">Source</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr
                  key={n.id}
                  onClick={() => openDetail(n.id)}
                  className="cursor-pointer border-t border-gray-800 hover:bg-gray-900"
                >
                  <td className="px-4 py-2 text-gray-200">{n.label}</td>
                  <td className="px-4 py-2 font-mono text-xs text-blue-400">
                    {canonicalKind(n.node_kind)}
                  </td>
                  <td className="px-4 py-2 text-gray-500">{n.source_domain}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="border-t border-gray-800 px-4 py-2 text-xs text-gray-600">
            {nodes.length} node(s), {edges.length} edge(s)
          </div>
        </div>
      )}

      {selectedId && (
        <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Node Detail</h2>
            <button
              onClick={() => setSelectedId(null)}
              className="text-xs text-gray-500 hover:text-gray-300"
            >
              Close
            </button>
          </div>
          {detailError ? (
            <div className="mt-3 text-sm text-red-400">{detailError}</div>
          ) : detail === null ? (
            <div className="mt-3 text-sm text-gray-500">Loading…</div>
          ) : (
            <div className="mt-3">
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Stat label="Kind" value={canonicalKind(detail.node.node_kind)} />
                <Stat label="Source" value={detail.node.source_domain} />
                <Stat label="Inbound" value={String(detail.inbound_count)} />
                <Stat label="Outbound" value={String(detail.outbound_count)} />
              </div>
              <div className="mt-4">
                <div className="mb-2 text-sm font-medium text-gray-400">
                  Relationships ({neighbors?.length ?? 0})
                </div>
                {neighbors === null ? (
                  <div className="text-xs text-gray-500">Loading…</div>
                ) : neighbors.length === 0 ? (
                  <div className="text-xs text-gray-600">No relationships recorded.</div>
                ) : (
                  <div className="space-y-2">
                    {neighbors.map((nb) => (
                      <div
                        key={nb.via_edge.id}
                        className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs"
                      >
                        <span className="font-mono text-blue-400">
                          {nb.via_edge.relationship_kind}
                        </span>
                        <span className="text-gray-600"> → </span>
                        <span className="text-gray-300">{nb.node.label}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-6">
        <h2 className="text-lg font-semibold text-white">Security Relationship Paths</h2>
        <p className="mt-1 text-xs text-gray-500">
          Bounded, cycle-safe relationship chains — not an attack path; no
          exploitability or risk score is computed.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <input
            value={startNodeId}
            onChange={(e) => setStartNodeId(e.target.value)}
            placeholder="Start node ID"
            className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <input
            value={endNodeId}
            onChange={(e) => setEndNodeId(e.target.value)}
            placeholder="End node ID"
            className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <button
            onClick={runPathQuery}
            disabled={pathLoading || !startNodeId || !endNodeId}
            className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {pathLoading ? "Searching…" : "Find Paths"}
          </button>
        </div>

        {pathError && (
          <div className="mt-3 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
            {pathError}
          </div>
        )}

        {paths !== null && (
          <div className="mt-3">
            {paths.length === 0 ? (
              <div className="text-xs text-gray-600">No relationship path found.</div>
            ) : (
              <div className="space-y-2">
                {paths.map((p, i) => (
                  <div
                    key={i}
                    className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 font-mono text-xs text-gray-400"
                  >
                    {p.node_ids.join(" → ")}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="text-sm font-bold text-white truncate">{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}
