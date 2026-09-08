import { describe, expect, it, afterEach } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { GraphWidget } from "@/components/dashboard/widgets/GraphWidget";
import type { GraphRendererProps } from "@/components/dashboard/graph/graphTypes";

afterEach(cleanup);

/** A fake renderer standing in for `ReactFlowGraphRenderer` — proves
 * `GraphWidget` only depends on the `GraphRenderer` contract, not on
 * `@xyflow/react` specifically, which is exactly the swappable-
 * renderer seam the platform-realization architecture requires. */
function FakeRenderer({ model }: GraphRendererProps) {
  return <div data-testid="fake-renderer">{model.nodes.length} nodes</div>;
}

describe("GraphWidget", () => {
  it("shows an empty state when the model has no nodes", () => {
    render(<GraphWidget id="g1" title="Attack Path" model={{ nodes: [], edges: [] }} />);
    expect(screen.getByText("No relationships to display.")).toBeInTheDocument();
  });

  it("delegates rendering to whichever GraphRenderer is supplied", () => {
    render(
      <GraphWidget
        id="g2"
        title="Attack Path"
        model={{ nodes: [{ id: "n1", label: "Node 1", kind: "asset" }], edges: [] }}
        renderer={FakeRenderer}
      />
    );
    expect(screen.getByTestId("fake-renderer")).toHaveTextContent("1 nodes");
  });
});
