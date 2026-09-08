import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as platform from "@/lib/platform";
import { socDashboardAggregator } from "@/components/dashboard/aggregation/socDashboardAggregator";
import DashboardPage from "./page";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/platform", async () => {
  const actual = await vi.importActual<typeof import("@/lib/platform")>("@/lib/platform");
  return { ...actual, getBootstrapStatus: vi.fn(), bootstrapSuperAdmin: vi.fn() };
});

// The page's only data dependency is the aggregator (see the
// Dashboard Aggregation Layer architecture note) — mocked here at
// that boundary. `socDashboardAggregator`'s own real data-shaping
// logic (severity counting, graceful degradation per source, the
// "awaiting platform integration" panels) has its own dedicated test
// file, `socDashboardAggregator.test.ts`.
vi.mock("@/components/dashboard/aggregation/socDashboardAggregator", () => ({
  socDashboardAggregator: { id: "soc-overview", load: vi.fn() },
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("DashboardPage", () => {
  it("renders the shell immediately, never gated behind a blocking loading state", () => {
    vi.mocked(socDashboardAggregator.load).mockReturnValue(new Promise(() => {})); // never resolves
    vi.mocked(platform.getBootstrapStatus).mockReturnValue(new Promise(() => {}));

    render(<DashboardPage />);

    expect(screen.getByText("Security Operations Command Center")).toBeInTheDocument();
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
    expect(screen.queryByText(/Loading/)).not.toBeInTheDocument();
  });

  it("an aggregator failure renders an error state with retry, never a blank or stuck page", async () => {
    vi.mocked(socDashboardAggregator.load).mockRejectedValue(new Error("network error"));
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("Failed to load dashboard data.")).toBeInTheDocument();
    });
    expect(screen.getByText("Retry")).toBeInTheDocument();
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
  });

  it("renders the composed widget spec once the aggregator resolves", async () => {
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });
    vi.mocked(socDashboardAggregator.load).mockResolvedValue({
      id: "soc-overview",
      widgets: [
        {
          type: "kpi",
          span: 1,
          viewModel: { id: "k1", label: "Critical Findings", value: 3, sublabel: "Require action" },
        },
      ],
    });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("Critical Findings")).toBeInTheDocument();
    });
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("loads with the default 24h time range on first render", async () => {
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });
    vi.mocked(socDashboardAggregator.load).mockResolvedValue({ id: "soc-overview", widgets: [] });

    render(<DashboardPage />);

    await waitFor(() =>
      expect(socDashboardAggregator.load).toHaveBeenCalledWith(
        expect.objectContaining({ timeRange: "24h" })
      )
    );
  });
});
