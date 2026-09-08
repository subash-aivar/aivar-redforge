import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup, within } from "@testing-library/react";
import * as remediationImpact from "@/lib/remediationImpact";
import RemediationImpactPage from "./page";

vi.mock("@/lib/remediationImpact", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/remediationImpact")>();
  return {
    ...actual,
    generatePlan: vi.fn(),
    listPlans: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mockAll() {
  vi.mocked(remediationImpact.listPlans).mockResolvedValue([]);
}

async function openGenerateModal() {
  const trigger = screen.getByText("Generate Plan");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Generate Exposure Reduction Plan" })).toBeInTheDocument();
  });
  return trigger;
}

describe("RemediationImpactPage — Generate Plan modal", () => {
  it("opens a labelled dialog with a real programmatic label on the plan budget field", async () => {
    mockAll();
    render(<RemediationImpactPage />);
    await waitFor(() => screen.getByText("Generate Plan"));
    await openGenerateModal();
    const field = screen.getByLabelText("Plan Budget", { exact: false });
    expect(field.id).toBeTruthy();
    expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("candidate remediation ID inputs are individually labelled, not anonymous", async () => {
    mockAll();
    render(<RemediationImpactPage />);
    await waitFor(() => screen.getByText("Generate Plan"));
    await openGenerateModal();
    expect(screen.getByLabelText("Remediation ID for candidate 1")).toBeInTheDocument();
  });

  it("requires at least one candidate with an ID and shows the error as role=alert", async () => {
    mockAll();
    render(<RemediationImpactPage />);
    await waitFor(() => screen.getByText("Generate Plan"));
    await openGenerateModal();

    fireEvent.click(within(screen.getByRole("dialog")).getByText("Generate Plan"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/At least one candidate/i);
    });
    expect(remediationImpact.generatePlan).not.toHaveBeenCalled();
  });

  it("Cancel closes the modal and sends no request", async () => {
    mockAll();
    render(<RemediationImpactPage />);
    await waitFor(() => screen.getByText("Generate Plan"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Generate Exposure Reduction Plan" })).not.toBeInTheDocument();
    expect(remediationImpact.generatePlan).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the trigger", async () => {
    mockAll();
    render(<RemediationImpactPage />);
    await waitFor(() => screen.getByText("Generate Plan"));
    const trigger = await openGenerateModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Generate Exposure Reduction Plan" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});
