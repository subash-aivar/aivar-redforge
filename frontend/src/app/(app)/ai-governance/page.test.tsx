import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as gov from "@/lib/aiGovernance";
import AIGovernancePage from "./page";
import type { Envelope } from "@/lib/aiGovernance";

vi.mock("@/lib/aiGovernance", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/aiGovernance")>();
  return {
    ...actual,
    draftEnvelope: vi.fn(),
    approveEnvelope: vi.fn(),
    suspendEnvelope: vi.fn(),
    getAdvisories: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function makeEnvelope(overrides: Partial<Envelope> = {}): Envelope {
  return {
    envelope_id: "env-123456789012",
    tenant_id: "tenant-1",
    ai_system_asset_id: "asset-1",
    state: "DRAFT",
    envelope_version: 1,
    action_categories: [],
    requires_human_approval_for: [],
    approved_by: null,
    ...overrides,
  };
}

describe("AIGovernancePage — form accessibility", () => {
  it("the asset ID and envelope ID lookup fields have real programmatic labels", () => {
    const { container } = render(<AIGovernancePage />);
    for (const name of ["AI System Asset ID", "Envelope ID"]) {
      const field = screen.getByLabelText(name, { exact: false });
      expect(field.id).toBeTruthy();
      expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
    }
  });

  it("no duplicate field ids exist on the page", () => {
    const { container } = render(<AIGovernancePage />);
    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("Approve and Suspend are explicit, unambiguous action names", async () => {
    vi.mocked(gov.draftEnvelope).mockResolvedValue(makeEnvelope());
    render(<AIGovernancePage />);

    fireEvent.change(screen.getByLabelText("AI System Asset ID", { exact: false }), {
      target: { value: "asset-1" },
    });
    fireEvent.click(screen.getByText("Draft"));

    await waitFor(() => {
      expect(screen.getByText("Approve")).toBeInTheDocument();
    });
    expect(screen.getByText("Suspend")).toBeInTheDocument();
  });

  it("drafting sends exactly the existing payload shape — no fabricated fields", async () => {
    vi.mocked(gov.draftEnvelope).mockResolvedValue(makeEnvelope());
    render(<AIGovernancePage />);

    fireEvent.change(screen.getByLabelText("AI System Asset ID", { exact: false }), {
      target: { value: "asset-42" },
    });
    fireEvent.click(screen.getByText("Draft"));

    await waitFor(() => {
      expect(gov.draftEnvelope).toHaveBeenCalledWith({ asset_id: "asset-42" });
    });
  });

  it("a failed draft shows a role=alert error, and approval state is never fabricated", async () => {
    vi.mocked(gov.draftEnvelope).mockRejectedValue(new Error("not found"));
    render(<AIGovernancePage />);

    fireEvent.change(screen.getByLabelText("AI System Asset ID", { exact: false }), {
      target: { value: "bad-asset" },
    });
    fireEvent.click(screen.getByText("Draft"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toBeInTheDocument();
    });
    expect(screen.queryByText("Approve")).not.toBeInTheDocument();
  });

  it("approval only ever reflects the real backend-returned state, never optimistic success", async () => {
    vi.mocked(gov.draftEnvelope).mockResolvedValue(makeEnvelope({ state: "DRAFT" }));
    vi.mocked(gov.approveEnvelope).mockResolvedValue(makeEnvelope({ state: "APPROVED" }));
    render(<AIGovernancePage />);

    fireEvent.change(screen.getByLabelText("AI System Asset ID", { exact: false }), {
      target: { value: "asset-1" },
    });
    fireEvent.click(screen.getByText("Draft"));
    await waitFor(() => screen.getByText("Approve"));

    fireEvent.click(screen.getByText("Approve"));

    await waitFor(() => {
      expect(gov.approveEnvelope).toHaveBeenCalledWith("env-123456789012", "analyst");
    });
    expect(screen.getByText("APPROVED")).toBeInTheDocument();
  });

  it("advisory lookup shows a role=alert error for an unknown envelope ID, without fabricating an advisory list", async () => {
    vi.mocked(gov.getAdvisories).mockRejectedValue(new Error("not found"));
    render(<AIGovernancePage />);

    fireEvent.change(screen.getByLabelText("Envelope ID", { exact: false }), {
      target: { value: "unknown-id" },
    });
    fireEvent.click(screen.getByText("Look Up"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(/No advisories found/);
    });
  });
});

async function draftEnvelope() {
  vi.mocked(gov.draftEnvelope).mockResolvedValue(makeEnvelope());
  render(<AIGovernancePage />);
  fireEvent.change(screen.getByLabelText("AI System Asset ID", { exact: false }), {
    target: { value: "asset-1" },
  });
  fireEvent.click(screen.getByText("Draft"));
  await waitFor(() => screen.getByText("Suspend"));
}

async function openSuspendModal() {
  const trigger = screen.getByText("Suspend");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: /Suspend Envelope/ })).toBeInTheDocument();
  });
  return trigger;
}

describe("AIGovernancePage — suspend flow (FormModal, no window.prompt)", () => {
  it("no window.prompt is called anywhere in the suspend flow", async () => {
    const promptSpy = vi.spyOn(window, "prompt");
    vi.mocked(gov.suspendEnvelope).mockResolvedValue(makeEnvelope({ state: "SUSPENDED" }));
    await draftEnvelope();

    await openSuspendModal();
    fireEvent.change(screen.getByLabelText("Suspension reason", { exact: false }), {
      target: { value: "policy violation" },
    });
    fireEvent.click(screen.getByText("Suspend Envelope"));

    await waitFor(() => expect(gov.suspendEnvelope).toHaveBeenCalled());
    expect(promptSpy).not.toHaveBeenCalled();
  });

  it("Suspend opens a FormModal with a real programmatic label on the reason field", async () => {
    await draftEnvelope();
    await openSuspendModal();
    const field = screen.getByLabelText("Suspension reason", { exact: false });
    expect(field.id).toBeTruthy();
    expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("empty submit shows a linked validation error and focuses the reason field", async () => {
    await draftEnvelope();
    await openSuspendModal();

    fireEvent.click(screen.getByText("Suspend Envelope"));

    const field = screen.getByLabelText("Suspension reason", { exact: false });
    await waitFor(() => {
      expect(field).toHaveAttribute("aria-invalid", "true");
    });
    const describedBy = field.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy!.split(" ")[0])).toHaveTextContent(
      "Suspension reason is required."
    );
    expect(field).toHaveFocus();
    expect(gov.suspendEnvelope).not.toHaveBeenCalled();
  });

  it("Cancel closes the modal and sends no request", async () => {
    await draftEnvelope();
    await openSuspendModal();
    fireEvent.change(screen.getByLabelText("Suspension reason", { exact: false }), {
      target: { value: "typed but cancelled" },
    });

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: /Suspend Envelope/ })).not.toBeInTheDocument();
    expect(gov.suspendEnvelope).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the Suspend trigger, without sending a request", async () => {
    await draftEnvelope();
    const trigger = await openSuspendModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: /Suspend Envelope/ })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(gov.suspendEnvelope).not.toHaveBeenCalled();
  });

  it("valid submit sends exactly the existing payload — no fabricated fields", async () => {
    vi.mocked(gov.suspendEnvelope).mockResolvedValue(makeEnvelope({ state: "SUSPENDED" }));
    await draftEnvelope();
    await openSuspendModal();

    fireEvent.change(screen.getByLabelText("Suspension reason", { exact: false }), {
      target: { value: "confirmed policy violation" },
    });
    fireEvent.click(screen.getByText("Suspend Envelope"));

    await waitFor(() => {
      expect(gov.suspendEnvelope).toHaveBeenCalledWith(
        "env-123456789012",
        "confirmed policy violation"
      );
    });
  });

  it("the submit button shows a loading state and cannot be clicked twice while the request is in flight", async () => {
    let resolveSuspend!: (v: Envelope) => void;
    vi.mocked(gov.suspendEnvelope).mockReturnValue(
      new Promise((resolve) => {
        resolveSuspend = resolve;
      })
    );
    await draftEnvelope();
    await openSuspendModal();
    fireEvent.change(screen.getByLabelText("Suspension reason", { exact: false }), {
      target: { value: "duplicate check" },
    });
    fireEvent.click(screen.getByText("Suspend Envelope"));

    await waitFor(() => {
      expect(screen.getByText("Suspending…")).toBeDisabled();
    });
    fireEvent.click(screen.getByText("Suspending…"));
    expect(gov.suspendEnvelope).toHaveBeenCalledTimes(1);

    resolveSuspend(makeEnvelope({ state: "SUSPENDED" }));
  });

  it("a server-side suspend failure is announced via role=alert and keeps the modal open — approval state is never confused with success", async () => {
    vi.mocked(gov.suspendEnvelope).mockRejectedValue(new Error("Suspend failed."));
    await draftEnvelope();
    await openSuspendModal();
    fireEvent.change(screen.getByLabelText("Suspension reason", { exact: false }), {
      target: { value: "attempt" },
    });
    fireEvent.click(screen.getByText("Suspend Envelope"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Suspend failed.");
    });
    expect(screen.getByRole("dialog", { name: /Suspend Envelope/ })).toBeInTheDocument();
    expect(screen.queryByText("SUSPENDED")).not.toBeInTheDocument();
  });

  it("success closes the modal and reflects only the real backend-returned envelope state", async () => {
    vi.mocked(gov.suspendEnvelope).mockResolvedValue(makeEnvelope({ state: "SUSPENDED" }));
    await draftEnvelope();
    await openSuspendModal();
    fireEvent.change(screen.getByLabelText("Suspension reason", { exact: false }), {
      target: { value: "confirmed policy violation" },
    });
    fireEvent.click(screen.getByText("Suspend Envelope"));

    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: /Suspend Envelope/ })).not.toBeInTheDocument();
    });
    expect(screen.getByText("SUSPENDED")).toBeInTheDocument();
  });

  it("no duplicate field ids exist while the suspend modal is open", async () => {
    await draftEnvelope();
    await openSuspendModal();

    const ids = Array.from(document.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
