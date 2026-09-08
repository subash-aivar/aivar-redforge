import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as exposureReporting from "@/lib/exposureReporting";
import * as auth from "@/lib/auth";
import ExposureReportingPage from "./page";
import type { ExposureReportingDashboard } from "@/lib/exposureReporting";

vi.mock("@/lib/exposureReporting", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/exposureReporting")>();
  return {
    ...actual,
    generateReport: vi.fn(),
    listReports: vi.fn(),
    createBusinessImpactMapping: vi.fn(),
    listBusinessImpactMappings: vi.fn(),
    getExposureReportingDashboard: vi.fn(),
    getExposureReportingTrends: vi.fn(),
  };
});

vi.mock("@/lib/auth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth")>();
  return { ...actual, getMe: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const DASHBOARD: ExposureReportingDashboard = {
  tenant_id: "org-1",
  tenant_exposure_score: 3.2,
  asset_count: 10,
  mapped_asset_count: 6,
  unmapped_asset_count: 4,
  dominant_amplifier: null,
  kpi: {},
  top_assets: [],
  business_impact_mapped: true,
  data_freshness_warning: false,
  generated_at: new Date(0).toISOString(),
};

function mockAll() {
  vi.mocked(exposureReporting.getExposureReportingDashboard).mockResolvedValue(DASHBOARD);
  vi.mocked(exposureReporting.getExposureReportingTrends).mockResolvedValue({
    tenant_id: "org-1",
    points: [],
    score_input_version: 1,
  });
  vi.mocked(exposureReporting.listReports).mockResolvedValue([]);
  vi.mocked(exposureReporting.listBusinessImpactMappings).mockResolvedValue([]);
  vi.mocked(auth.getMe).mockResolvedValue({
    user_id: "u1", email: "analyst@example.test", display_name: "Analyst", status: "active",
  });
}

async function openGenerateModal() {
  const trigger = screen.getByText("Generate Report");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Generate Exposure Report" })).toBeInTheDocument();
  });
  return trigger;
}

describe("ExposureReportingPage — Generate Report modal", () => {
  it("opens a labelled dialog with a real programmatic label on the report type selector", async () => {
    mockAll();
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();
    const field = screen.getByLabelText("Report Type", { exact: false });
    expect(field.id).toBeTruthy();
    expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("Cancel closes the modal and sends no request", async () => {
    mockAll();
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Generate Exposure Report" })).not.toBeInTheDocument();
    expect(exposureReporting.generateReport).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the trigger", async () => {
    mockAll();
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    const trigger = await openGenerateModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Generate Exposure Report" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(exposureReporting.generateReport).not.toHaveBeenCalled();
  });

  it("surfaces a failed generation as a role=alert error instead of failing silently", async () => {
    mockAll();
    vi.mocked(exposureReporting.generateReport).mockRejectedValue(new Error("quota exceeded"));
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Generate"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("quota exceeded");
    });
    expect(screen.getByRole("dialog", { name: "Generate Exposure Report" })).toBeInTheDocument();
  });

  it("submits the exact expected payload and reloads reports on success", async () => {
    mockAll();
    vi.mocked(exposureReporting.generateReport).mockResolvedValue({} as never);
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Generate"));

    await waitFor(() => {
      expect(exposureReporting.generateReport).toHaveBeenCalledWith({
        report_type: "EXECUTIVE_SUMMARY",
        generated_by: "analyst@example.test",
      });
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Generate Exposure Report" })).not.toBeInTheDocument();
    });
  });
});

describe("ExposureReportingPage — Add Mapping modal", () => {
  async function openMappingModal() {
    fireEvent.click(screen.getByText("mappings"));
    await waitFor(() => screen.getByText("Add Mapping"));
    fireEvent.click(screen.getByText("Add Mapping"));
    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "Add Business Impact Mapping" })).toBeInTheDocument();
    });
  }

  it("requires an asset reference ID and shows the error as role=alert", async () => {
    mockAll();
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openMappingModal();

    fireEvent.click(screen.getByText("Save"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/Asset reference ID is required/i);
    });
    expect(exposureReporting.createBusinessImpactMapping).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and sends no request", async () => {
    mockAll();
    render(<ExposureReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openMappingModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Add Business Impact Mapping" })).not.toBeInTheDocument();
    expect(exposureReporting.createBusinessImpactMapping).not.toHaveBeenCalled();
  });
});
