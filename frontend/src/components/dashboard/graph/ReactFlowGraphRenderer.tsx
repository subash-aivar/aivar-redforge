"use client";

import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useMemo } from "react";
import { SEVERITY_HEX } from "@/design-system/tokens";
import type { GraphRendererProps } from "@/components/dashboard/graph/graphTypes";

/**
 * The ONLY file in this codebase that imports `@xyflow/react`.
 *
 * Implements `GraphRenderer` (see graphTypes.ts) by converting the
 * renderer-agnostic `GraphModel` into React Flow's `Node[]`/`Edge[]`.
 * If React Flow is ever swapped out, this is the only file that needs
 * replacing — `GraphWidget` and every caller are unaffected.
 */
export function ReactFlowGraphRenderer({ model, onNodeClick, height = 420 }: GraphRendererProps) {
  const nodes: Node[] = useMemo(
    () =>
      model.nodes.map((n, index) => ({
        id: n.id,
        data: { label: n.label },
        position: n.position ?? { x: (index % 6) * 160, y: Math.floor(index / 6) * 100 },
        style: {
          background: "#111827",
          color: "#e5e7eb",
          border: `1px solid ${n.severity ? SEVERITY_HEX[n.severity] : "#374151"}`,
          borderRadius: 8,
          fontSize: 12,
          padding: 8,
        },
      })),
    [model.nodes]
  );

  const edges: Edge[] = useMemo(
    () =>
      model.edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        label: e.label,
        style: { stroke: "#4b5563" },
        labelStyle: { fill: "#9ca3af", fontSize: 10 },
      })),
    [model.edges]
  );

  return (
    <div style={{ height }} className="overflow-hidden rounded-lg border border-gray-800">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodeClick={(_, node) => onNodeClick?.(node.id)}
        fitView
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#1f2937" gap={16} />
        <Controls showInteractive={false} />
        <MiniMap
          maskColor="rgba(17, 24, 39, 0.7)"
          nodeColor="#374151"
          style={{ background: "#111827" }}
        />
      </ReactFlow>
    </div>
  );
}
