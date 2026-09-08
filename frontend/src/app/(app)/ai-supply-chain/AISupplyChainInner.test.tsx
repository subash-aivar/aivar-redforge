import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as aiSupplyChain from "@/lib/aiSupplyChain";
import AISupplyChainInner from "./AISupplyChainInner";
import type { ModelProvenance } from "@/lib/aiSupplyChain";

vi.mock("@/lib/aiSupplyChain");

let searchParams = new URLSearchParams();
vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParams,
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  searchParams = new URLSearchParams();
});

describe("AISupplyChainInner cross-module pivot", () => {
  it("auto-looks-up the provenance record for ?highlight=<provenance_id> — a real pivot from AI Posture", async () => {
    searchParams = new URLSearchParams("highlight=prov-1");
    vi.mocked(aiSupplyChain.getProvenance).mockResolvedValue({
      provenance_id: "prov-1",
      tenant_id: "t1",
      ai_system_asset_id: "asset-1",
      model_origin: "huggingface.co/acme/model",
      integrity_status: "Verified",
      operational_status: "Active",
      artifact_size_bytes: 5_000_000,
      verification_method_latest: "IndependentHash",
      trust_delegation_note_latest: "",
      chain_entry_count: 3,
      consecutive_failures: 0,
    });

    render(<AISupplyChainInner />);

    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "huggingface.co/acme/model" })).toBeInTheDocument();
    });
    expect(aiSupplyChain.getProvenance).toHaveBeenCalledWith("prov-1");
  });

  it("shows an honest error, never fabricated data, when no provenance record is found", async () => {
    searchParams = new URLSearchParams("highlight=missing-id");
    vi.mocked(aiSupplyChain.getProvenance).mockRejectedValue(new Error("not found"));

    render(<AISupplyChainInner />);

    await waitFor(() => {
      const alert = screen.getByRole("alert");
      expect(alert).toHaveTextContent("No provenance record found for this ID.");
    });
  });
});

function makeProvenance(overrides: Partial<ModelProvenance> = {}): ModelProvenance {
  return {
    provenance_id: "prov-1",
    tenant_id: "t1",
    ai_system_asset_id: "asset-1",
    model_origin: "huggingface.co/acme/model",
    integrity_status: "Verified",
    operational_status: "Active",
    artifact_size_bytes: 5_000_000,
    verification_method_latest: "IndependentHash",
    trust_delegation_note_latest: "",
    chain_entry_count: 3,
    consecutive_failures: 0,
    ...overrides,
  };
}

describe("AISupplyChainInner — form accessibility", () => {
  it("the provenance ID lookup field has a real programmatic label", () => {
    const { container } = render(<AISupplyChainInner />);
    const field = screen.getByLabelText("Provenance ID", { exact: false });
    expect(field.id).toBeTruthy();
    expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("the retrieval URI field is labelled and explicitly named once a record is loaded", async () => {
    vi.mocked(aiSupplyChain.getProvenance).mockResolvedValue(makeProvenance());
    render(<AISupplyChainInner />);
    fireEvent.change(screen.getByLabelText("Provenance ID", { exact: false }), {
      target: { value: "prov-1" },
    });
    fireEvent.click(screen.getByText("Look Up"));

    await waitFor(() => screen.getByRole("dialog"));
    expect(screen.getByLabelText(/Retrieval URI to verify against/i)).toBeInTheDocument();
    expect(screen.getByText("Verify")).toBeInTheDocument();
    expect(screen.getByText("Manual Reset")).toBeInTheDocument();
  });

  it("manual reset never claims verification succeeded — it reflects only the real backend-returned state", async () => {
    vi.mocked(aiSupplyChain.getProvenance).mockResolvedValue(makeProvenance({ integrity_status: "Failed" }));
    vi.mocked(aiSupplyChain.manualResetVerification).mockResolvedValue(
      makeProvenance({ integrity_status: "Pending" })
    );
    render(<AISupplyChainInner />);
    fireEvent.change(screen.getByLabelText("Provenance ID", { exact: false }), {
      target: { value: "prov-1" },
    });
    fireEvent.click(screen.getByText("Look Up"));
    await waitFor(() => screen.getByText("Manual Reset"));

    fireEvent.click(screen.getByText("Manual Reset"));

    await waitFor(() => {
      expect(aiSupplyChain.manualResetVerification).toHaveBeenCalledWith("prov-1");
    });
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.queryByText("Failed")).not.toBeInTheDocument();
  });
});
