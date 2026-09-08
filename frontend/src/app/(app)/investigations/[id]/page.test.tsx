import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as investigations from "@/lib/investigations";
import InvestigationDetailPage from "./page";
import type { InvestigationCase, EvidenceLink, InvestigationTimelineEvent } from "@/lib/investigations";

const routerBack = vi.fn();
vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "case-1" }),
  useRouter: () => ({ back: routerBack }),
}));

vi.mock("@/lib/investigations", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/investigations")>();
  return {
    ...actual,
    getInvestigation: vi.fn(),
    getInvestigationTimeline: vi.fn(),
    getInvestigationEvidence: vi.fn(),
    acknowledgeInvestigation: vi.fn(),
    startInvestigation: vi.fn(),
    resolveInvestigation: vi.fn(),
    listInvestigationAttackPaths: vi.fn(),
    recomputeInvestigationAttackPath: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function makeCase(overrides: Partial<InvestigationCase> = {}): InvestigationCase {
  return {
    id: "case-1",
    organization_id: "org-1",
    title: "Correlated credential-access chain",
    summary: "Multiple domains observed the same entity within the window.",
    status: "OPEN",
    severity: "HIGH",
    confidence: "HIGH",
    source_domains: ["behavior", "network"],
    involved_entities: [{ type: "user", id: "user-1" }],
    evidence_count: 2,
    first_observed_at: new Date(0).toISOString(),
    last_observed_at: new Date(1000).toISOString(),
    opened_at: new Date(0).toISOString(),
    acknowledged_at: null,
    investigating_at: null,
    resolved_at: null,
    resolution_reason: null,
    resolution_notes: null,
    version: 1,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function makeEvidence(overrides: Partial<EvidenceLink> = {}): EvidenceLink {
  return {
    id: "ev-1",
    source_domain: "behavior",
    source_entity_type: "user",
    source_entity_id: "user-1",
    event_type: "anomaly_detected",
    severity: "HIGH",
    observability: "OBSERVED",
    observed_at: new Date(0).toISOString(),
    correlation_reason: "shared entity",
    ...overrides,
  } as EvidenceLink;
}

function mockAll(opts: {
  investigation?: InvestigationCase;
  timeline?: InvestigationTimelineEvent[];
  evidence?: EvidenceLink[];
}) {
  vi.mocked(investigations.getInvestigation).mockResolvedValue(opts.investigation ?? makeCase());
  vi.mocked(investigations.getInvestigationTimeline).mockResolvedValue(opts.timeline ?? []);
  vi.mocked(investigations.getInvestigationEvidence).mockResolvedValue(opts.evidence ?? []);
  vi.mocked(investigations.listInvestigationAttackPaths).mockResolvedValue([]);
}

async function renderLoaded(opts: Parameters<typeof mockAll>[0] = {}) {
  mockAll(opts);
  render(<InvestigationDetailPage />);
  await waitFor(() => {
    expect(screen.getByText((opts.investigation ?? makeCase()).title)).toBeInTheDocument();
  });
}

describe("InvestigationDetailPage — action error surfacing (no longer silently swallowed)", () => {
  it("a failed Acknowledge is announced via role=alert, not silently ignored", async () => {
    await renderLoaded();
    vi.mocked(investigations.acknowledgeInvestigation).mockRejectedValue(
      new Error("Acknowledge denied by policy")
    );

    fireEvent.click(screen.getByText("Acknowledge"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Acknowledge denied by policy");
    });
  });

  it("a failed Start Investigation is announced via role=alert", async () => {
    await renderLoaded();
    vi.mocked(investigations.startInvestigation).mockRejectedValue(new Error("Start denied"));

    fireEvent.click(screen.getByText("Start Investigation"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Start denied");
    });
  });
});

describe("InvestigationDetailPage — resolve flow (FormModal)", () => {
  it("Resolve opens a labelled FormModal dialog", async () => {
    await renderLoaded();
    const trigger = screen.getByText("Resolve");
    trigger.focus();
    fireEvent.click(trigger);

    expect(screen.getByRole("dialog", { name: "Resolve Investigation" })).toBeInTheDocument();
    const field = screen.getByLabelText("Resolution reason", { exact: false });
    expect(field.id).toBeTruthy();
    expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
  });

  it("Cancel closes the modal and sends no request", async () => {
    await renderLoaded();
    fireEvent.click(screen.getByText("Resolve"));
    await waitFor(() => screen.getByRole("dialog", { name: "Resolve Investigation" }));

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Resolve Investigation" })).not.toBeInTheDocument();
    expect(investigations.resolveInvestigation).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the Resolve trigger", async () => {
    await renderLoaded();
    const trigger = screen.getByText("Resolve");
    trigger.focus();
    fireEvent.click(trigger);
    await waitFor(() => screen.getByRole("dialog", { name: "Resolve Investigation" }));

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Resolve Investigation" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
    expect(investigations.resolveInvestigation).not.toHaveBeenCalled();
  });

  it("valid submit sends exactly the existing payload — no fabricated fields", async () => {
    await renderLoaded();
    vi.mocked(investigations.resolveInvestigation).mockResolvedValue({
      case_id: "case-1",
      status: "RESOLVED",
    });
    fireEvent.click(screen.getByText("Resolve"));
    await waitFor(() => screen.getByRole("dialog", { name: "Resolve Investigation" }));

    fireEvent.change(screen.getByLabelText("Notes", { exact: false }), {
      target: { value: "confirmed true positive, remediated" },
    });
    fireEvent.click(screen.getByText("Resolve Case"));

    await waitFor(() => {
      expect(investigations.resolveInvestigation).toHaveBeenCalledWith(
        "case-1",
        "TRUE_POSITIVE_REMEDIATED",
        "confirmed true positive, remediated"
      );
    });
  });

  it("a server-side resolve failure is announced via role=alert and keeps the modal open", async () => {
    await renderLoaded();
    vi.mocked(investigations.resolveInvestigation).mockRejectedValue(
      new Error("Resolve failed: version conflict")
    );
    fireEvent.click(screen.getByText("Resolve"));
    await waitFor(() => screen.getByRole("dialog", { name: "Resolve Investigation" }));

    fireEvent.click(screen.getByText("Resolve Case"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Resolve failed: version conflict");
    });
    expect(screen.getByRole("dialog", { name: "Resolve Investigation" })).toBeInTheDocument();
  });

  it("no duplicate field ids exist while the resolve modal is open", async () => {
    const { container } = render(<InvestigationDetailPage />);
    mockAll({});
    await waitFor(() => screen.getByText("Correlated credential-access chain"));
    fireEvent.click(screen.getByText("Resolve"));
    await waitFor(() => screen.getByRole("dialog", { name: "Resolve Investigation" }));

    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("Resolve is absent once the case is already resolved (policy-driven visibility)", async () => {
    await renderLoaded({ investigation: makeCase({ status: "RESOLVED" }) });
    expect(screen.queryByText("Resolve")).not.toBeInTheDocument();
  });
});

describe("InvestigationDetailPage — honest states", () => {
  it("surfaces a real load failure, not a fabricated case", async () => {
    vi.mocked(investigations.getInvestigation).mockRejectedValue(new Error("not found"));
    vi.mocked(investigations.getInvestigationTimeline).mockResolvedValue([]);
    vi.mocked(investigations.getInvestigationEvidence).mockResolvedValue([]);
    vi.mocked(investigations.listInvestigationAttackPaths).mockResolvedValue([]);
    render(<InvestigationDetailPage />);

    await waitFor(() => {
      expect(screen.getByText("not found")).toBeInTheDocument();
    });
  });
});
