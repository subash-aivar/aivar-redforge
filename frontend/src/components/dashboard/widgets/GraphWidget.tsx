"use client";

import { Card } from "@/design-system/primitives/Card";
import { SectionHeader } from "@/design-system/primitives/SectionHeader";
import { EmptyState } from "@/design-system/primitives/States";
import { ReactFlowGraphRenderer } from "@/components/dashboard/graph/ReactFlowGraphRenderer";
import type { GraphModel, GraphRenderer } from "@/components/dashboard/graph/graphTypes";

export interface GraphViewModel {
  id: string;
  title: string;
  model: GraphModel;
  emptyMessage?: string;
  height?: number;
  onNodeClick?: (nodeId: string) => void;
  /** Defaults to the React Flow implementation. Pass a different
   * `GraphRenderer` to swap the rendering engine without touching any
   * dashboard/aggregation code — this is the seam the platform-
   * realization architecture requires. */
  renderer?: GraphRenderer;
}

/** Reusable graph widget for relationship views (attack paths, ATT&CK
 * technique chains, entity graphs). Delegates all rendering to the
 * pluggable `GraphRenderer` — never imports a graph library directly. */
export function GraphWidget({
  title,
  model,
  emptyMessage = "No relationships to display.",
  height = 420,
  onNodeClick,
  renderer: Renderer = ReactFlowGraphRenderer,
}: GraphViewModel) {
  return (
    <Card>
      <SectionHeader title={title} />
      <div className="mt-3">
        {model.nodes.length === 0 ? (
          <EmptyState message={emptyMessage} />
        ) : (
          <Renderer model={model} onNodeClick={onNodeClick} height={height} />
        )}
      </div>
    </Card>
  );
}
