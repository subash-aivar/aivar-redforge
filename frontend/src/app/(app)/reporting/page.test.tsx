import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as reporting from "@/lib/reporting";
import * as auth from "@/lib/auth";
import ReportingPage from "./page";
import type { ReportTemplate } from "@/lib/reporting";

vi.mock("@/lib/reporting", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/reporting")>();
  return {
    ...actual,
    listTemplates: vi.fn(),
    listReportInstances: vi.fn(),
    listDeliveryAudit: vi.fn(),
    generateReportOnDemand: vi.fn(),
    createScheduledReport: vi.fn(),
    downloadExportedReport: vi.fn(),
  };
});
vi.mock("@/lib/auth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/auth")>();
  return { ...actual, getMe: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function makeTemplate(overrides: Partial<ReportTemplate> = {}): ReportTemplate {
  return {
    template_id: "tmpl-1",
    report_type: "EXECUTIVE_SUMMARY",
    name: "Executive Summary",
    sections: ["overview", "findings"],
    ...overrides,
  };
}

function mockAll(opts: { templates?: ReportTemplate[] }) {
  vi.mocked(reporting.listTemplates).mockResolvedValue(opts.templates ?? [makeTemplate()]);
  vi.mocked(reporting.listReportInstances).mockResolvedValue([]);
  vi.mocked(reporting.listDeliveryAudit).mockResolvedValue([]);
  vi.mocked(auth.getMe).mockResolvedValue({
    user_id: "u1", email: "analyst@example.test", display_name: "Analyst", status: "active",
  });
}

async function openGenerateModal() {
  const trigger = screen.getByText("Generate Report");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Generate Report" })).toBeInTheDocument();
  });
  return trigger;
}

describe("ReportingPage — Generate Report modal", () => {
  it("opens a labelled FormModal with a real programmatic label on the template selector", async () => {
    mockAll({});
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));

    await openGenerateModal();
    const field = screen.getByLabelText("Template", { exact: false });
    expect(field.id).toBeTruthy();
    expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("Cancel closes the modal and sends no request", async () => {
    mockAll({});
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Generate Report" })).not.toBeInTheDocument();
    expect(reporting.generateReportOnDemand).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the trigger", async () => {
    mockAll({});
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    const trigger = await openGenerateModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Generate Report" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(reporting.generateReportOnDemand).not.toHaveBeenCalled();
  });

  it("valid submit sends exactly the existing payload — no fabricated fields", async () => {
    mockAll({});
    vi.mocked(reporting.generateReportOnDemand).mockResolvedValue({
      instance_id: "inst-1",
      tenant_id: "t1",
      template_id: "tmpl-1",
      report_type: "EXECUTIVE_SUMMARY",
      status: "PENDING",
      trigger: "manual",
      narrative: "",
      narrative_variant: "",
      content: {},
      artifact_ref: null,
      error_reason: null,
      generated_by: "analyst@example.test",
      created_at: new Date(0).toISOString(),
      completed_at: null,
      schedule_id: null,
    });
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Generate"));

    await waitFor(() => {
      expect(reporting.generateReportOnDemand).toHaveBeenCalledWith({
        template_id: "tmpl-1",
        generated_by: "analyst@example.test",
      });
    });
  });

  it("a server-side generation failure is announced via role=alert and keeps the modal open", async () => {
    mockAll({});
    vi.mocked(reporting.generateReportOnDemand).mockRejectedValue(new Error("Template disabled"));
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Generate"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Template disabled");
    });
    expect(screen.getByRole("dialog", { name: "Generate Report" })).toBeInTheDocument();
  });

  it("the Generate action is disabled, not fabricated, when no templates exist", async () => {
    mockAll({ templates: [] });
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Generate Report"));
    await openGenerateModal();

    expect(screen.getByText("No templates available.")).toBeInTheDocument();
    expect(screen.getByText("Generate")).toBeDisabled();
  });
});

describe("ReportingPage — Schedule Report modal", () => {
  it("opens a labelled FormModal with real labels on every field", async () => {
    mockAll({});
    const { container } = render(<ReportingPage />);
    await waitFor(() => screen.getByText("Schedule Report"));

    const trigger = screen.getByText("Schedule Report");
    fireEvent.click(trigger);
    await waitFor(() => screen.getByRole("dialog", { name: "Schedule Report" }));

    for (const name of ["Template", "Cron schedule", "Cadence (minutes)", "Recipients"]) {
      const field = screen.getByLabelText(name, { exact: false });
      expect(field.id).toBeTruthy();
      expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
    }
  });

  it("valid submit sends exactly the existing payload — no fabricated fields", async () => {
    mockAll({});
    vi.mocked(reporting.createScheduledReport).mockResolvedValue({
      schedule_id: "sched-1",
      tenant_id: "t1",
      template_id: "tmpl-1",
      schedule: "0 * * * *",
      cadence_minutes: 60,
      status: "ACTIVE",
      next_run_at: new Date(0).toISOString(),
      last_run_at: null,
      parameters: {},
      recipients: [],
      created_by: "analyst@example.test",
      created_at: new Date(0).toISOString(),
    });
    render(<ReportingPage />);
    await waitFor(() => screen.getByText("Schedule Report"));
    fireEvent.click(screen.getByText("Schedule Report"));
    await waitFor(() => screen.getByRole("dialog", { name: "Schedule Report" }));

    fireEvent.change(screen.getByLabelText("Recipients", { exact: false }), {
      target: { value: "alice@example.com, bob@example.com" },
    });
    fireEvent.click(screen.getByText("Schedule"));

    await waitFor(() => {
      expect(reporting.createScheduledReport).toHaveBeenCalledWith({
        template_id: "tmpl-1",
        schedule: "0 * * * *",
        cadence_minutes: 60,
        recipients: ["alice@example.com", "bob@example.com"],
        created_by: "analyst@example.test",
      });
    });
  });

  it("no duplicate field ids exist while both the generate and schedule flows are considered", async () => {
    mockAll({});
    const { container } = render(<ReportingPage />);
    await waitFor(() => screen.getByText("Schedule Report"));
    fireEvent.click(screen.getByText("Schedule Report"));
    await waitFor(() => screen.getByRole("dialog", { name: "Schedule Report" }));

    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("ReportingPage — honest empty/error states", () => {
  it("renders an honest empty state, never a fabricated report list", async () => {
    mockAll({});
    render(<ReportingPage />);
    await waitFor(() => {
      expect(screen.getByText("No reports generated yet.")).toBeInTheDocument();
    });
  });
});
