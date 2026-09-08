import { describe, it, expect, vi, beforeEach } from "vitest";
import { api, ApiError } from "@/lib/api";
import {
  getAgentDeviations,
  getInventoryDashboard,
  getRiskRegister,
  getShadowDiscoveryReport,
  getSupplyChainIntegrity,
} from "@/lib/ai-posture";

vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual<typeof import("@/lib/api")>("@/lib/api");
  return { ...actual, api: { get: vi.fn(), post: vi.fn() } };
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("ai-posture read-model clients — honest 404 handling", () => {
  it("returns real data when the risk register projection exists", async () => {
    vi.mocked(api.get).mockResolvedValue({
      tenant_id: "t1",
      entries: [{ asset_id: "a1", composite_score: 7.2, score_input_version: "v1", computed_at: "x", is_stale: false }],
    });
    const result = await getRiskRegister();
    expect(result.entries).toHaveLength(1);
    expect(result.empty).toBeUndefined();
  });

  it("treats a 404 (no risk register computed yet) as an honest empty state, not an error", async () => {
    vi.mocked(api.get).mockRejectedValue(new ApiError(404, "NOT_FOUND", "not found", {}));
    const result = await getRiskRegister();
    expect(result.empty).toBe(true);
    expect(result.entries).toEqual([]);
  });

  it("re-throws non-404 errors instead of masking them as empty", async () => {
    vi.mocked(api.get).mockRejectedValue(new ApiError(500, "SERVER_ERROR", "boom", {}));
    await expect(getRiskRegister()).rejects.toThrow("boom");
  });

  it("treats a 404 on supply-chain integrity as empty", async () => {
    vi.mocked(api.get).mockRejectedValue(new ApiError(404, "NOT_FOUND", "not found", {}));
    const result = await getSupplyChainIntegrity();
    expect(result.empty).toBe(true);
    expect(result.models).toEqual([]);
  });

  it("treats a 404 on agent deviations as empty", async () => {
    vi.mocked(api.get).mockRejectedValue(new ApiError(404, "NOT_FOUND", "not found", {}));
    const result = await getAgentDeviations();
    expect(result.empty).toBe(true);
    expect(result.deviations).toEqual([]);
  });

  // Regression tests for a real bug found in browser QA: the live
  // backend returns an identical 404 ("<Model> not found: <org_id>")
  // for ALL FIVE ai-posture read-model endpoints on a fresh tenant, but
  // `getInventoryDashboard`/`getShadowDiscoveryReport` were never wired
  // to the same `getOrEmpty` honest-empty-state helper the other three
  // already used — so their raw backend exception text rendered
  // directly in the UI as a red error banner instead of an empty state.
  it("treats a 404 on the AI asset inventory dashboard as empty, not a raw error", async () => {
    vi.mocked(api.get).mockRejectedValue(
      new ApiError(404, "NOT_FOUND", "AIAssetInventoryDashboard not found: org-1", {})
    );
    const result = await getInventoryDashboard();
    expect(result.empty).toBe(true);
    expect(result.assets).toEqual([]);
  });

  it("returns real data when the AI asset inventory dashboard exists", async () => {
    vi.mocked(api.get).mockResolvedValue({
      tenant_id: "t1",
      assets: [{ asset_id: "a1", ai_system_kind: "llm", lifecycle_state: "active" }],
      last_scan_at: "2026-01-01T00:00:00Z",
      configured_discovery_sources: ["aws"],
      coverage_scope: "full",
    });
    const result = await getInventoryDashboard();
    expect(result.assets).toHaveLength(1);
    expect(result.empty).toBeUndefined();
  });

  it("treats a 404 on shadow AI discovery as empty, not a raw error", async () => {
    vi.mocked(api.get).mockRejectedValue(
      new ApiError(404, "NOT_FOUND", "ShadowAIDiscoveryReport not found: org-1", {})
    );
    const result = await getShadowDiscoveryReport();
    expect(result.empty).toBe(true);
    expect(result.alerts).toEqual([]);
  });

  it("re-throws non-404 errors from the inventory/shadow endpoints instead of masking them", async () => {
    vi.mocked(api.get).mockRejectedValue(new ApiError(500, "SERVER_ERROR", "boom", {}));
    await expect(getInventoryDashboard()).rejects.toThrow("boom");
    await expect(getShadowDiscoveryReport()).rejects.toThrow("boom");
  });
});
