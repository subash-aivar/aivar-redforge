import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/lib/api";
import { getProvenance, manualResetVerification, verifyProvenance } from "@/lib/aiSupplyChain";

vi.mock("@/lib/api");

beforeEach(() => {
  vi.clearAllMocks();
});

describe("aiSupplyChain client — real route regression coverage", () => {
  it("gets a provenance record from the real /provenances/{id} route, not the dead /artifacts route", async () => {
    vi.mocked(api.get).mockResolvedValue({});
    await getProvenance("prov-1");
    expect(api.get).toHaveBeenCalledWith("/api/v1/ai-supply-chain/provenances/prov-1");
  });

  it("verifies provenance with the real request shape", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await verifyProvenance("prov-1", { retrieval_uri: "https://example.com/model.bin" });
    expect(api.post).toHaveBeenCalledWith(
      "/api/v1/ai-supply-chain/provenances/prov-1/verify",
      { retrieval_uri: "https://example.com/model.bin" }
    );
  });

  it("manual-resets verification on the real route", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await manualResetVerification("prov-1");
    expect(api.post).toHaveBeenCalledWith("/api/v1/ai-supply-chain/provenances/prov-1/manual-reset", {});
  });
});
