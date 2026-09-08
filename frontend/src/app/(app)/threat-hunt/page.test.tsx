import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as huntLib from "@/lib/threat-hunt";
import ThreatHuntPage from "./page";
import type { ThreatHuntCandidate } from "@/lib/threat-hunt";

vi.mock("@/lib/threat-hunt", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/threat-hunt")>();
  return {
    ...actual,
    listCandidates: vi.fn(),
    promoteCandidate: vi.fn(),
    rejectCandidate: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function makeCandidate(overrides: Partial<ThreatHuntCandidate> = {}): ThreatHuntCandidate {
  return {
    candidate_id: "candidate-1256789012",
    tenant_id: "tenant-1",
    status: "pending_review",
    confidence_score: 0.72,
    detection_rule_format: "sigma",
    technique_coverage: ["T1059"],
    anomaly_signal_count: 3,
    ...overrides,
  };
}

describe("ThreatHuntPage — candidate suggestions, never decisions", () => {
  it("candidate status is rendered as its own distinct state (never as a confirmed detection)", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate({ status: "pending_review" })]);
    render(<ThreatHuntPage />);

    await waitFor(() => {
      expect(screen.getByText("pending review")).toBeInTheDocument();
    });
    expect(screen.getByText("Pending Review")).toBeInTheDocument(); // KPI label, real backend-derived count
  });

  it("the page subtitle honestly frames candidates as AI-surfaced suggestions awaiting analyst triage", () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([]);
    render(<ThreatHuntPage />);
    expect(
      screen.getByText("AI-surfaced hunt candidates awaiting analyst triage")
    ).toBeInTheDocument();
  });

  it("Promote and Reject are explicit, unambiguous action names in the candidate drawer", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    render(<ThreatHuntPage />);

    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));

    await waitFor(() => {
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    });
    expect(screen.getByText("Promote")).toBeInTheDocument();
    expect(screen.getByText("Reject")).toBeInTheDocument();
  });

  it("an honest empty state is shown, never a fabricated candidate", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([]);
    render(<ThreatHuntPage />);
    await waitFor(() => {
      expect(screen.getByText("No hunt candidates.")).toBeInTheDocument();
    });
  });
});

async function openRejectModal() {
  const trigger = screen.getByText("Reject");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: /Reject Candidate/ })).toBeInTheDocument();
  });
  return trigger;
}

describe("ThreatHuntPage — reject flow (FormModal, no window.prompt)", () => {
  it("no window.prompt is called anywhere in the reject flow", async () => {
    const promptSpy = vi.spyOn(window, "prompt");
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.change(screen.getByLabelText("Rejection reason", { exact: false }), {
      target: { value: "false positive" },
    });
    fireEvent.click(screen.getByText("Reject Candidate"));

    await waitFor(() => expect(huntLib.rejectCandidate).toHaveBeenCalled());
    expect(promptSpy).not.toHaveBeenCalled();
  });

  it("Reject opens a FormModal with a real programmatic label on the reason field", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    const { container } = render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    const field = screen.getByLabelText("Rejection reason", { exact: false });
    expect(field.id).toBeTruthy();
    expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("empty submit shows a linked validation error and focuses the reason field", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.click(screen.getByText("Reject Candidate"));

    const field = screen.getByLabelText("Rejection reason", { exact: false });
    await waitFor(() => {
      expect(field).toHaveAttribute("aria-invalid", "true");
    });
    const describedBy = field.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy!.split(" ")[0])).toHaveTextContent(
      "Rejection reason is required."
    );
    expect(field).toHaveFocus();
    expect(huntLib.rejectCandidate).not.toHaveBeenCalled();
  });

  it("Cancel closes the modal and sends no request", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.change(screen.getByLabelText("Rejection reason", { exact: false }), {
      target: { value: "typed but cancelled" },
    });
    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: /Reject Candidate/ })).not.toBeInTheDocument();
    expect(huntLib.rejectCandidate).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the Reject trigger, without sending a request", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    const trigger = await openRejectModal();
    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: /Reject Candidate/ })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(huntLib.rejectCandidate).not.toHaveBeenCalled();
  });

  it("valid submit sends exactly the existing payload — no fabricated fields", async () => {
    const candidate = makeCandidate();
    vi.mocked(huntLib.listCandidates).mockResolvedValue([candidate]);
    vi.mocked(huntLib.rejectCandidate).mockResolvedValue(undefined as never);
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.change(screen.getByLabelText("Rejection reason", { exact: false }), {
      target: { value: "confirmed benign, no action needed" },
    });
    fireEvent.click(screen.getByText("Reject Candidate"));

    await waitFor(() => {
      expect(huntLib.rejectCandidate).toHaveBeenCalledWith(
        candidate.candidate_id,
        "analyst",
        "confirmed benign, no action needed"
      );
    });
  });

  it("the submit button shows a loading state and cannot be clicked twice while the request is in flight", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    let resolveReject!: () => void;
    vi.mocked(huntLib.rejectCandidate).mockReturnValue(
      new Promise((resolve) => {
        resolveReject = () => resolve(undefined as never);
      })
    );
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.change(screen.getByLabelText("Rejection reason", { exact: false }), {
      target: { value: "duplicate" },
    });
    fireEvent.click(screen.getByText("Reject Candidate"));

    await waitFor(() => {
      expect(screen.getByText("Rejecting…")).toBeDisabled();
    });
    fireEvent.click(screen.getByText("Rejecting…"));
    expect(huntLib.rejectCandidate).toHaveBeenCalledTimes(1);

    resolveReject();
  });

  it("a server-side rejection failure is announced via role=alert and keeps the modal open", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    vi.mocked(huntLib.rejectCandidate).mockRejectedValue(new Error("Reject failed: candidate already promoted"));
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.change(screen.getByLabelText("Rejection reason", { exact: false }), {
      target: { value: "stale data" },
    });
    fireEvent.click(screen.getByText("Reject Candidate"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Reject failed: candidate already promoted");
    });
    expect(screen.getByRole("dialog", { name: /Reject Candidate/ })).toBeInTheDocument();
  });

  it("success closes the modal, closes the drawer, and reloads the candidate list — preserving existing refresh behavior", async () => {
    const candidate = makeCandidate();
    vi.mocked(huntLib.listCandidates).mockResolvedValue([candidate]);
    vi.mocked(huntLib.rejectCandidate).mockResolvedValue(undefined as never);
    render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));

    await openRejectModal();
    fireEvent.change(screen.getByLabelText("Rejection reason", { exact: false }), {
      target: { value: "confirmed benign" },
    });
    fireEvent.click(screen.getByText("Reject Candidate"));

    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: /Reject Candidate/ })).not.toBeInTheDocument();
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument(); // drawer also closed, matches prior behavior
    expect(huntLib.listCandidates).toHaveBeenCalledTimes(2); // initial load + reload after success
  });

  it("no duplicate field ids exist while the reject modal is open", async () => {
    vi.mocked(huntLib.listCandidates).mockResolvedValue([makeCandidate()]);
    const { container } = render(<ThreatHuntPage />);
    await waitFor(() => screen.getByText(/candidate-12/));
    fireEvent.click(screen.getByText(/candidate-12/));
    await waitFor(() => screen.getByText("Reject"));
    await openRejectModal();

    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
