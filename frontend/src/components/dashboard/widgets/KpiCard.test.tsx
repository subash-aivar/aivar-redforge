import { describe, expect, it, afterEach } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { KpiCard } from "@/components/dashboard/widgets/KpiCard";

afterEach(cleanup);

describe("KpiCard", () => {
  it("renders label, value, and sublabel", () => {
    render(<KpiCard id="k1" label="Critical Findings" value={3} sublabel="Require action" />);
    expect(screen.getByText("Critical Findings")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
    expect(screen.getByText("Require action")).toBeInTheDocument();
  });

  it("renders a trend badge using the caller-supplied tone, not an assumed direction=bad mapping", () => {
    render(
      <KpiCard
        id="k2"
        label="Compliance Score"
        value="92%"
        sublabel="This period"
        trend={{ direction: "up", percent: 5, tone: "positive" }}
      />
    );
    expect(screen.getByText("+5%")).toBeInTheDocument();
  });
});
