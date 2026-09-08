import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as attackSurfaceManagement from "@/lib/attackSurfaceManagement";
import AttackSurfaceAssetsInner from "./AttackSurfaceAssetsInner";
import type { Asset } from "@/lib/attackSurfaceManagement";

vi.mock("@/lib/attackSurfaceManagement", async () => {
  const actual = await vi.importActual<typeof import("@/lib/attackSurfaceManagement")>(
    "@/lib/attackSurfaceManagement"
  );
  return {
    ...actual,
    getExposureStateCoverage: vi.fn().mockResolvedValue({
      unknown: 0,
      not_exposed: 1,
      internet_facing: 2,
      exposed_high_risk: 0,
    }),
    listAssets: vi.fn(),
  };
});

let searchParams = new URLSearchParams();
vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParams,
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  searchParams = new URLSearchParams();
});

function makeAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    asset_id: "asset-1",
    tenant_id: "t1",
    asset_type: "external",
    primary_identifier: "app.example.com",
    discovery_source: "passive_dns",
    classification: "unknown",
    criticality: "medium",
    exposure_state: "internet_facing",
    lifecycle_state: "active",
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    domain_name: "example.com",
    subdomain: "app",
    ip_address: null,
    ownership: null,
    ports: [],
    certificates: [],
    dns_records: [],
    fingerprints: [],
    ...overrides,
  };
}

describe("AttackSurfaceAssetsInner cross-module pivot", () => {
  it("auto-opens the drawer for the asset matching ?highlight=<asset_id> — a real pivot from an attack-surface correlation", async () => {
    searchParams = new URLSearchParams("highlight=asset-2");
    vi.mocked(attackSurfaceManagement.listAssets).mockResolvedValue({
      items: [makeAsset({ asset_id: "asset-1" }), makeAsset({ asset_id: "asset-2", primary_identifier: "api.example.com" })],
      count: 2,
    });

    render(<AttackSurfaceAssetsInner />);

    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "api.example.com" })).toBeInTheDocument();
    });
  });

  it("renders normally with no highlight param, no drawer auto-opened", async () => {
    searchParams = new URLSearchParams();
    vi.mocked(attackSurfaceManagement.listAssets).mockResolvedValue({
      items: [makeAsset()],
      count: 1,
    });

    render(<AttackSurfaceAssetsInner />);

    await waitFor(() => {
      expect(screen.getByText("app.example.com")).toBeInTheDocument();
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
