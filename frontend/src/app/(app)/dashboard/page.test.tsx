import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as api from "@/lib/api";
import * as platform from "@/lib/platform";
import DashboardPage from "./page";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { ...actual.api, get: vi.fn() } };
});

vi.mock("@/lib/platform", async () => {
  const actual = await vi.importActual<typeof import("@/lib/platform")>("@/lib/platform");
  return { ...actual, getBootstrapStatus: vi.fn(), bootstrapSuperAdmin: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("DashboardPage", () => {
  it("renders the shell immediately, never gated behind a blocking loading state", () => {
    vi.mocked(api.api.get).mockReturnValue(new Promise(() => {})); // never resolves
    vi.mocked(platform.getBootstrapStatus).mockReturnValue(new Promise(() => {}));

    render(<DashboardPage />);

    expect(screen.getByText("Security Overview")).toBeInTheDocument();
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
  });

  it("every dashboard-data endpoint failing still renders the shell with empty/default metrics — never a blank or stuck page", async () => {
    vi.mocked(api.api.get).mockRejectedValue(new Error("network error"));
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });

    render(<DashboardPage />);

    await waitFor(() => {
      // Promise.allSettled never rejects the outer chain, so the page
      // renders normally with all-empty defaults rather than hanging —
      // this assertion is what actually protects that contract.
      expect(
        screen.getByText("No AI targets registered. Register a target to begin security validation.")
      ).toBeInTheDocument();
    });
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
    expect(screen.getAllByText("0").length).toBeGreaterThan(0);
  });

  it("a partial failure (e.g. findings endpoint down, others fine) still renders the other metrics from whichever calls succeeded", async () => {
    vi.mocked(platform.getBootstrapStatus).mockResolvedValue({ available: false });
    vi.mocked(api.api.get).mockImplementation((path: string) => {
      if (path === "/api/v1/findings") return Promise.reject(new Error("findings down"));
      if (path === "/api/v1/health") return Promise.resolve({ status: "healthy", version: "0.1.0" });
      return Promise.resolve([]);
    });

    render(<DashboardPage />);

    await waitFor(() => {
      expect(screen.getByText("healthy")).toBeInTheDocument();
    });
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
  });
});
