import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as platform from "@/lib/platform";
import * as productEdition from "@/lib/productEdition";
import { socDashboardAggregator } from "@/components/dashboard/aggregation/socDashboardAggregator";
import { networkDashboardAggregator } from "@/components/dashboard/aggregation/networkDashboardAggregator";
import DashboardPage from "./page";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/platform", async () => {
  const actual = await vi.importActual<typeof import("@/lib/platform")>("@/lib/platform");
  return { ...actual, getBootstrapStatus: vi.fn(), bootstrapSuperAdmin: vi.fn() };
});

vi.mock("@/lib/productEdition", async () => {
  const actual = await vi.importActual<typeof import("@/lib/productEdition")>(
    "@/lib/productEdition"
  );
  return { ...actual, getProductEdition: vi.fn(() => "full") };
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

// Same boundary for the Network Defense edition's aggregator — its own
// real data-shaping logic has its own dedicated test file,
// `networkDashboardAggregator.test.ts`.
vi.mock("@/components/dashboard/aggregation/networkDashboardAggregator", () => ({
  networkDashboardAggregator: { id: "network-defense-overview", load: vi.fn() },
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
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

describe("DashboardPage — network_defense edition", () => {
  afterEach(() => {
    vi.mocked(productEdition.getProductEdition).mockReturnValue("full");
  });

  it("uses the Network Defense aggregator and title, never the Full one", async () => {
    vi.mocked(productEdition.getProductEdition).mockReturnValue("network_defense");
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });
    vi.mocked(networkDashboardAggregator.load).mockResolvedValue({
      id: "network-defense-overview",
      widgets: [
        {
          type: "kpi",
          span: 1,
          viewModel: { id: "ddos-incidents", label: "DDoS Incidents", value: 0, sublabel: "Currently active" },
        },
      ],
    });

    render(<DashboardPage />);

    expect(screen.getByText("Network Defense Overview")).toBeInTheDocument();
    expect(screen.queryByText("Security Operations Command Center")).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("DDoS Incidents")).toBeInTheDocument();
    });
    expect(socDashboardAggregator.load).not.toHaveBeenCalled();
  });

  it("renders the Network quick-links panel instead of the platform bootstrap card", async () => {
    vi.mocked(productEdition.getProductEdition).mockReturnValue("network_defense");
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: true });
    vi.mocked(networkDashboardAggregator.load).mockResolvedValue({
      id: "network-defense-overview",
      widgets: [],
    });

    render(<DashboardPage />);

    expect(screen.getByText("DDoS Defense")).toBeInTheDocument();
    expect(screen.getByText("Network Security")).toBeInTheDocument();
    expect(screen.getByText("Investigations")).toBeInTheDocument();
  });

  it("an aggregator failure renders an honest error state, never a blank page", async () => {
    vi.mocked(productEdition.getProductEdition).mockReturnValue("network_defense");
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });
    vi.mocked(networkDashboardAggregator.load).mockRejectedValue(new Error("network error"));

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("Failed to load dashboard data.")).toBeInTheDocument();
    });
    expect(screen.getByText("Retry")).toBeInTheDocument();
  });
});
