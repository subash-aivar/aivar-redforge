import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as networkSecurity from "@/lib/networkSecurity";
import NetworkSecurityPage from "./page";
import type {
  NetworkInventoryEntry,
  NetworkMonitoringPolicy,
} from "@/lib/networkSecurity";

vi.mock("@/lib/networkSecurity", async () => {
  const actual = await vi.importActual<typeof import("@/lib/networkSecurity")>(
    "@/lib/networkSecurity"
  );
  return {
    ...actual,
    getInventory: vi.fn(),
    listMonitoringPolicies: vi.fn(),
    createMonitoringPolicy: vi.fn(),
    activatePolicy: vi.fn(),
    pausePolicy: vi.fn(),
    resumePolicy: vi.fn(),
    disablePolicy: vi.fn(),
    runNow: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function makeInventoryEntry(
  overrides: Partial<NetworkInventoryEntry> = {}
): NetworkInventoryEntry {
  return {
    asset_id: "asset-1",
    address: "10.20.30.40",
    address_classification: "private",
    observed_services: ["https (tcp/443)"],
    active_condition_count: 1,
    last_observed_at: "2026-07-13T00:00:00Z",
    monitoring_status: "monitored",
    ...overrides,
  };
}

function makePolicy(overrides: Partial<NetworkMonitoringPolicy> = {}): NetworkMonitoringPolicy {
  return {
    id: "policy-1",
    organization_id: "org-1",
    target_asset_id: "asset-1",
    requester_user_id: "user-1",
    profile: "network_standard",
    cadence: "daily",
    lifecycle: "active",
    next_due_at: "2026-07-14T00:00:00Z",
    last_scheduled_at: null,
    ...overrides,
  };
}

describe("NetworkSecurityPage", () => {
  it("renders inventory and monitoring policies once loaded", async () => {
    vi.mocked(networkSecurity.getInventory).mockResolvedValue([makeInventoryEntry()]);
    vi.mocked(networkSecurity.listMonitoringPolicies).mockResolvedValue([makePolicy()]);

    render(<NetworkSecurityPage />);

    await waitFor(() => {
      expect(screen.getByText("10.20.30.40")).toBeInTheDocument();
    });
    expect(screen.getByText("private")).toBeInTheDocument();
    expect(screen.getAllByText("active").length).toBeGreaterThan(0);
  });

  it("shows an empty state when there is no network inventory", async () => {
    vi.mocked(networkSecurity.getInventory).mockResolvedValue([]);
    vi.mocked(networkSecurity.listMonitoringPolicies).mockResolvedValue([]);

    render(<NetworkSecurityPage />);

    await waitFor(() => {
      expect(screen.getByText(/No network assets observed yet\./)).toBeInTheDocument();
    });
  });

  it("shows an error state when the inventory fetch fails", async () => {
    vi.mocked(networkSecurity.getInventory).mockRejectedValue(new Error("boom"));
    vi.mocked(networkSecurity.listMonitoringPolicies).mockResolvedValue([]);

    render(<NetworkSecurityPage />);

    await waitFor(() => {
      expect(screen.getByText("boom")).toBeInTheDocument();
    });
  });
});
