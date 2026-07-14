"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { getNeighbors, getNode, getOverview, type GraphOverview, type GraphNode, type NodeDetail, type Neighbor } from "@/lib/securityGraph";
import { listZoneAssignments, ZONE_LABELS } from "@/lib/commandCenter";
import { AsyncContent, InvestigationDrawer, Panel, PageHeader, SeverityBadge, useAsync, type DrawerField } from "@/components/cc";

const KIND_COLOR: Record<string, string> = {
  asset: "#60a5fa",
  ai_asset: "#60a5fa",
  identity: "#34d399",
  service: "#a78bfa",
  security_condition: "#fb923c",
  security_correlation: "#f87171",
  network: "#38bdf8",
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  info: "#9ca3af",
};

const ZONE_RING: Record<string, string> = {
  internet_edge: "#f87171",
  dmz: "#fb923c",
  internal: "#34d399",
  management: "#a78bfa",
  cloud: "#38bdf8",
  restricted: "#f472b6",
};

function nodeColor(n: GraphNode): string {
  if (n.node_kind === "security_condition" && n.attributes.severity) {
    return SEVERITY_COLOR[n.attributes.severity.toLowerCase()] ?? KIND_COLOR.security_condition;
  }
  return KIND_COLOR[n.node_kind] ?? "#9ca3af";
}

// Deterministic layered layout: nodes are grouped into columns by kind,
// stacked vertically within each column. No physics/animation — pure,
// reproducible geometry that is safe under the strict CSP (no CDN, no
// external chart library, all inline SVG).
function layout(overview: GraphOverview) {
  const RENDER_CAP = 150;
  const nodes = overview.nodes.slice(0, RENDER_CAP);
  const kinds = Array.from(new Set(nodes.map((n) => n.node_kind))).sort();
  const colX = new Map<string, number>();
  kinds.forEach((k, i) => colX.set(k, 120 + i * 220));
  const perKindCount = new Map<string, number>();
  const pos = new Map<string, { x: number; y: number; kind: string; label: string }>();
  for (const n of nodes) {
    const idx = perKindCount.get(n.node_kind) ?? 0;
    perKindCount.set(n.node_kind, idx + 1);
    pos.set(n.id, {
      x: colX.get(n.node_kind) ?? 120,
      y: 70 + idx * 46,
      kind: n.node_kind,
      label: n.label,
    });
  }
  const maxRows = Math.max(1, ...Array.from(perKindCount.values()));
  const width = 120 + kinds.length * 220;
  const height = 70 + maxRows * 46 + 30;
  const edges = overview.edges.filter((e) => pos.has(e.source_node_id) && pos.has(e.target_node_id));
  return { nodes, pos, edges, kinds, width, height, rendered: nodes.length };
}

export default function NetworkMapPage() {
  const graph = useAsync(() => getOverview(), []);
  const zones = useAsync(() => listZoneAssignments(), []);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const nodeDetail = useAsync<NodeDetail>(
    () => (selectedId ? getNode(selectedId) : Promise.reject(new Error("no selection"))),
    [selectedId]
  );
  const neighbors = useAsync<Neighbor[]>(
    () => (selectedId ? getNeighbors(selectedId, "both") : Promise.resolve([])),
    [selectedId]
  );

  const zoneByAsset = useMemo(() => {
    const m = new Map<string, string>();
    for (const z of zones.data ?? []) m.set(z.asset_id, z.zone_type);
    return m;
  }, [zones.data]);

  const computedLayout = useMemo(() => (graph.data ? layout(graph.data) : null), [graph.data]);

  // Pan/zoom state — pure inline-SVG viewBox manipulation, CSP-safe, no
  // external library.
  const [view, setView] = useState<{ x: number; y: number; w: number; h: number } | null>(null);
  const dragRef = useRef<{ startX: number; startY: number; viewX: number; viewY: number } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  useEffect(() => {
    if (!view && computedLayout) {
      setView({ x: 0, y: 0, w: computedLayout.width, h: computedLayout.height });
    }
  }, [view, computedLayout]);

  function onWheel(e: React.WheelEvent<SVGSVGElement>) {
    if (!view) return;
    e.preventDefault();
    const factor = e.deltaY > 0 ? 1.1 : 0.9;
    const newW = Math.max(200, Math.min(view.w * factor, 4000));
    const newH = Math.max(150, Math.min(view.h * factor, 3000));
    setView({ x: view.x, y: view.y, w: newW, h: newH });
  }

  function onPointerDown(e: React.PointerEvent<SVGSVGElement>) {
    if (!view) return;
    dragRef.current = { startX: e.clientX, startY: e.clientY, viewX: view.x, viewY: view.y };
  }
  function onPointerMove(e: React.PointerEvent<SVGSVGElement>) {
    if (!dragRef.current || !view || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const scaleX = view.w / rect.width;
    const scaleY = view.h / rect.height;
    const dx = (e.clientX - dragRef.current.startX) * scaleX;
    const dy = (e.clientY - dragRef.current.startY) * scaleY;
    setView({ ...view, x: dragRef.current.viewX - dx, y: dragRef.current.viewY - dy });
  }
  function onPointerUp() {
    dragRef.current = null;
  }
  function resetView(baseW: number, baseH: number) {
    setView({ x: 0, y: 0, w: baseW, h: baseH });
  }

  const selectedNode = selectedId ?? null;

  const drawerFields: DrawerField[] = (() => {
    if (!selectedNode) return [];
    const fields: DrawerField[] = [];
    if (nodeDetail.data) {
      const n = nodeDetail.data.node;
      fields.push({ label: "Kind", value: n.node_kind.replace(/_/g, " ") });
      fields.push({ label: "Label", value: n.label });
      fields.push({ label: "Source domain", value: n.source_domain });
      fields.push({ label: "Source entity ID", value: <span className="font-mono text-[11px]">{n.source_entity_id}</span> });
      const zone = zoneByAsset.get(n.source_entity_id);
      if (zone) fields.push({ label: "Network zone", value: ZONE_LABELS[zone] ?? zone });
      for (const [k, v] of Object.entries(n.attributes)) {
        fields.push({ label: k.replace(/_/g, " "), value: k === "severity" ? <SeverityBadge severity={v} /> : v });
      }
      fields.push({ label: "Inbound relationships", value: nodeDetail.data.inbound_count });
      fields.push({ label: "Outbound relationships", value: nodeDetail.data.outbound_count });
    }
    if (neighbors.data && neighbors.data.length > 0) {
      fields.push({
        label: "Neighbors",
        value: (
          <ul className="space-y-1">
            {neighbors.data.slice(0, 25).map((nb) => (
              <li key={nb.node.id} className="text-xs text-gray-300">
                <span className="text-gray-500">{nb.via_edge.relationship_kind.replace(/_/g, " ")}</span> → {nb.node.label}
              </li>
            ))}
          </ul>
        ),
      });
    }
    return fields;
  })();

  return (
    <div>
      <PageHeader
        title="Security Relationship Map"
        subtitle="A security-relationship graph projected from real inventory, conditions, and correlations. This is an exposure relationship view — it is NOT a live-probed topology and NOT an attack path; no exploitability is computed or implied."
      />
      <Panel>
        <AsyncContent
          state={graph}
          empty={(g) => g.nodes.length === 0}
          emptyLabel="No graph nodes yet. Nodes are projected as assets, conditions, and correlations are discovered."
        >
          {(g) => {
            const l = computedLayout ?? layout(g);
            const activeView = view ?? { x: 0, y: 0, w: l.width, h: l.height };
            const hasZoneData = (zones.data ?? []).length > 0;
            return (
              <div>
                <div className="mb-3 flex flex-wrap items-center gap-3 text-[11px] text-gray-400">
                  {l.kinds.map((k) => (
                    <span key={k} className="inline-flex items-center gap-1">
                      <span
                        className="inline-block h-2.5 w-2.5 rounded-full"
                        style={{ backgroundColor: KIND_COLOR[k] ?? "#9ca3af" }}
                      />
                      {k.replace(/_/g, " ")}
                    </span>
                  ))}
                  {hasZoneData && (
                    <>
                      <span className="h-3 w-px bg-gray-800" />
                      {Object.entries(ZONE_RING).map(([z, color]) => (
                        <span key={z} className="inline-flex items-center gap-1">
                          <span className="inline-block h-2.5 w-2.5 rounded-full border-2" style={{ borderColor: color }} />
                          {ZONE_LABELS[z] ?? z}
                        </span>
                      ))}
                    </>
                  )}
                  <span className="ml-auto flex items-center gap-2 text-gray-600">
                    {g.node_count} nodes total{g.truncated ? " (backend-truncated)" : ""}
                    {l.rendered < g.nodes.length ? ` · rendering first ${l.rendered}` : ""}
                    <button
                      type="button"
                      onClick={() => resetView(l.width, l.height)}
                      className="rounded border border-gray-800 px-2 py-0.5 text-gray-400 hover:text-gray-200"
                    >
                      Reset view
                    </button>
                  </span>
                </div>
                <div className="overflow-hidden rounded-lg border border-gray-800 bg-gray-950/40">
                  <svg
                    ref={svgRef}
                    viewBox={`${activeView.x} ${activeView.y} ${activeView.w} ${activeView.h}`}
                    style={{ width: "100%", height: 480, cursor: dragRef.current ? "grabbing" : "grab" }}
                    role="img"
                    aria-label="Security relationship graph — scroll to zoom, drag to pan"
                    onWheel={onWheel}
                    onPointerDown={onPointerDown}
                    onPointerMove={onPointerMove}
                    onPointerUp={onPointerUp}
                    onPointerLeave={onPointerUp}
                  >
                    {l.edges.map((e) => {
                      const a = l.pos.get(e.source_node_id)!;
                      const b = l.pos.get(e.target_node_id)!;
                      const touchesSelected =
                        selectedNode && (e.source_node_id === selectedNode || e.target_node_id === selectedNode);
                      return (
                        <line
                          key={e.id}
                          x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                          stroke={touchesSelected ? "#f87171" : "#374151"}
                          strokeWidth={touchesSelected ? 2 : 1}
                          opacity={selectedNode && !touchesSelected ? 0.25 : 1}
                        />
                      );
                    })}
                    {l.nodes.map((n) => {
                      const p = l.pos.get(n.id)!;
                      const zone = zoneByAsset.get(n.source_entity_id);
                      const isSelected = n.id === selectedNode;
                      const dimmed = selectedNode && !isSelected && !l.edges.some(
                        (e) =>
                          (e.source_node_id === selectedNode && e.target_node_id === n.id) ||
                          (e.target_node_id === selectedNode && e.source_node_id === n.id)
                      );
                      return (
                        <g
                          key={n.id}
                          onClick={() => setSelectedId(n.id)}
                          style={{ cursor: "pointer" }}
                          opacity={dimmed ? 0.35 : 1}
                        >
                          {zone && (
                            <circle cx={p.x} cy={p.y} r="10" fill="none" stroke={ZONE_RING[zone] ?? "#9ca3af"} strokeWidth="2" />
                          )}
                          <circle
                            cx={p.x} cy={p.y}
                            r={isSelected ? 9 : 7}
                            fill={nodeColor(n)}
                            stroke={isSelected ? "#fff" : "none"}
                            strokeWidth={isSelected ? 1.5 : 0}
                          />
                          <text
                            x={p.x + 14} y={p.y + 4}
                            className="fill-gray-300" style={{ fontSize: 11 }}
                          >
                            {p.label.length > 24 ? `${p.label.slice(0, 24)}…` : p.label}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                </div>
                <div className="mt-2 text-[11px] text-gray-600">
                  Scroll to zoom, drag to pan, click a node to focus its relationships and open the investigation drawer.
                </div>
              </div>
            );
          }}
        </AsyncContent>
      </Panel>

      <InvestigationDrawer
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        title={nodeDetail.data?.node.label ?? "Loading…"}
        subtitle="Security relationship map · node detail"
        fields={drawerFields}
      />
    </div>
  );
}
