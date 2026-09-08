import type { Severity } from "@/design-system/tokens";

/**
 * Renderer-agnostic graph model.
 *
 * Nothing in the rest of the app (aggregation layer, dashboards,
 * pages) should ever import `@xyflow/react` types directly — they
 * build a `GraphModel` and hand it to `GraphWidget`, which delegates
 * to whichever `GraphRenderer` is configured. Swapping the renderer
 * (e.g. to Cytoscape.js for graph-analytics needs a future milestone
 * might have) means writing one new file that implements
 * `GraphRenderer` — zero changes anywhere else.
 */

export interface GraphNode {
  id: string;
  label: string;
  /** A coarse category the renderer may use for icon/color choices
   * (e.g. "asset", "actor", "technique", "indicator") — intentionally
   * a free string, not a closed enum, since different dashboards graph
   * different domains. */
  kind: string;
  severity?: Severity;
  /** Optional explicit layout position. If omitted, the renderer picks
   * an automatic layout. */
  position?: { x: number; y: number };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
}

export interface GraphModel {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphRendererProps {
  model: GraphModel;
  onNodeClick?: (nodeId: string) => void;
  height?: number;
}

/** The contract every graph renderer implementation must satisfy. */
export type GraphRenderer = (props: GraphRendererProps) => React.JSX.Element;
