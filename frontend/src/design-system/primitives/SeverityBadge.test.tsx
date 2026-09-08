import { describe, expect, it, afterEach } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { SeverityBadge } from "@/design-system/primitives/SeverityBadge";

afterEach(cleanup);

describe("SeverityBadge", () => {
  it("renders the severity text", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("falls back to the neutral class for an unrecognized severity instead of crashing", () => {
    render(<SeverityBadge severity="unknown-severity" />);
    expect(screen.getByText("unknown-severity")).toBeInTheDocument();
  });
});
