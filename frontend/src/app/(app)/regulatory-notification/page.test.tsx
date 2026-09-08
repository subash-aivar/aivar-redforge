import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup, within } from "@testing-library/react";
import * as regulatoryNotification from "@/lib/regulatoryNotification";
import RegulatoryNotificationPage from "./page";

vi.mock("@/lib/regulatoryNotification", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/regulatoryNotification")>();
  return {
    ...actual,
    startClocks: vi.fn(),
    getDeadlineDashboard: vi.fn(),
  };
});

vi.mock("next/navigation", () => ({
  useSearchParams: () => new URLSearchParams(),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mockAll() {
  vi.mocked(regulatoryNotification.getDeadlineDashboard).mockResolvedValue([]);
}

async function openStartClocksModal() {
  const trigger = screen.getByText("Start Clocks");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Start Regulatory Notification Clocks" })).toBeInTheDocument();
  });
  return trigger;
}

describe("RegulatoryNotificationPage — Start Clocks modal", () => {
  it("opens a labelled dialog with a real programmatic label on the Incident ID field", async () => {
    mockAll();
    render(<RegulatoryNotificationPage />);
    await waitFor(() => screen.getByText("Start Clocks"));
    await openStartClocksModal();
    const field = screen.getByLabelText("Incident ID", { exact: false });
    expect(field.id).toBeTruthy();
    expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("requires an incident ID and shows the error as role=alert", async () => {
    mockAll();
    render(<RegulatoryNotificationPage />);
    await waitFor(() => screen.getByText("Start Clocks"));
    await openStartClocksModal();

    fireEvent.click(within(screen.getByRole("dialog")).getByText("Start Clocks"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/Incident ID is required/i);
    });
    expect(regulatoryNotification.startClocks).not.toHaveBeenCalled();
  });

  it("Cancel closes the modal and sends no request", async () => {
    mockAll();
    render(<RegulatoryNotificationPage />);
    await waitFor(() => screen.getByText("Start Clocks"));
    await openStartClocksModal();

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Start Regulatory Notification Clocks" })).not.toBeInTheDocument();
    expect(regulatoryNotification.startClocks).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the trigger", async () => {
    mockAll();
    render(<RegulatoryNotificationPage />);
    await waitFor(() => screen.getByText("Start Clocks"));
    const trigger = await openStartClocksModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Start Regulatory Notification Clocks" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("toggling a regime chip reflects aria-pressed state", async () => {
    mockAll();
    render(<RegulatoryNotificationPage />);
    await waitFor(() => screen.getByText("Start Clocks"));
    await openStartClocksModal();

    const chip = screen.getByText("GDPR ART33");
    expect(chip).toHaveAttribute("aria-pressed", "false");
    fireEvent.click(chip);
    expect(chip).toHaveAttribute("aria-pressed", "true");
  });

  it("submits the exact expected payload and reloads on success", async () => {
    mockAll();
    vi.mocked(regulatoryNotification.startClocks).mockResolvedValue([]);
    render(<RegulatoryNotificationPage />);
    await waitFor(() => screen.getByText("Start Clocks"));
    await openStartClocksModal();

    fireEvent.change(screen.getByLabelText("Incident ID", { exact: false }), {
      target: { value: "incident-123" },
    });
    fireEvent.click(within(screen.getByRole("dialog")).getByText("Start Clocks"));

    await waitFor(() => {
      expect(regulatoryNotification.startClocks).toHaveBeenCalledWith("incident-123", undefined);
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Start Regulatory Notification Clocks" })).not.toBeInTheDocument();
    });
  });
});
