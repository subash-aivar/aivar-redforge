import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { api } from "@/lib/api";
import * as validationOperations from "@/lib/validationOperations";
import * as assetsLib from "@/lib/assets";
import TargetsPage from "./page";
import type { Target, Finding } from "@/lib/types";
import type { ValidationExecution } from "@/lib/validationOperations";
import type { Asset } from "@/lib/assets";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, get: vi.fn(), post: vi.fn() } };
});
vi.mock("@/lib/validationOperations", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/validationOperations")>();
  return { ...actual, listExecutions: vi.fn() };
});
vi.mock("@/lib/assets", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/assets")>();
  return { ...actual, listAssets: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function makeTarget(overrides: Partial<Target> = {}): Target {
  return {
    id: "target-1",
    organization_id: "org-1",
    name: "QA Test Target",
    description: "",
    target_type: "llm_application",
    provider: "openai",
    endpoint: "https://api.openai.com/v1/chat/completions",
    status: "active",
    tags: [],
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function makeExecution(overrides: Partial<ValidationExecution> = {}): ValidationExecution {
  return {
    id: "exec-1",
    organization_id: "org-1",
    target_id: "target-1",
    requester_user_id: "user-1",
    profile: "safe_active_baseline_v1",
    status: "denied",
    policy_decision_id: null,
    policy_reason_code: "AUTHORIZATION_NOT_FOUND",
    cancellation_requested: false,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    started_at: new Date(1000).toISOString(),
    completed_at: new Date(2000).toISOString(),
    failure_reason: "",
    steps: [],
    plan_summary: {
      initial_step_count: 0,
      adaptive_step_count: 0,
      discovered_address_count: 0,
      reachable_port_count: 0,
      validated_service_count: 0,
      condition_count: 0,
    },
    ...overrides,
  };
}

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-1",
    organization_id: "org-1",
    run_id: "run-1",
    target_id: "target-1",
    evidence_ids: [],
    title: "Test finding",
    description: "",
    severity: "high",
    risk_score: 7.2,
    status: "open",
    recommendation: "",
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function makeAsset(overrides: Partial<Asset> = {}): Asset {
  return {
    id: "asset-1",
    organization_id: "org-1",
    asset_type: "ai_application",
    name: "QA Test Target",
    description: "",
    external_id: "redforge_target_id:target-1",
    discovery_source: "manual",
    lifecycle_stage: "discovery",
    health_status: "unknown",
    first_observed_at: new Date(0).toISOString(),
    last_observed_at: new Date(0).toISOString(),
    relationship_count: 0,
    associated_target_id: "target-1",
    ...overrides,
  };
}

function mockAll(opts: {
  targets?: Target[];
  executions?: ValidationExecution[];
  findings?: Finding[];
  assets?: Asset[];
}) {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path === "/api/v1/targets") return Promise.resolve(opts.targets ?? []);
    if (path === "/api/v1/findings") return Promise.resolve(opts.findings ?? []);
    return Promise.reject(new Error(`unexpected path: ${path}`));
  });
  vi.mocked(validationOperations.listExecutions).mockResolvedValue(opts.executions ?? []);
  vi.mocked(assetsLib.listAssets).mockResolvedValue(opts.assets ?? []);
}

describe("TargetsPage", () => {
  it("derives KPI counts from real target/execution/finding relationships", async () => {
    mockAll({
      targets: [makeTarget({ id: "t1" }), makeTarget({ id: "t2", name: "Second Target", status: "inactive" })],
      executions: [makeExecution({ target_id: "t1" })],
      findings: [makeFinding({ target_id: "t1" })],
      assets: [],
    });

    render(<TargetsPage />);

    await waitFor(() => {
      expect(screen.getByText("Total Targets")).toBeInTheDocument();
    });

    // 2 total, 1 active, 1 with validation runs, 1 with open findings
    const kpiValues = screen.getAllByText(/^[0-9]+$/).map((el) => el.textContent);
    expect(kpiValues).toContain("2"); // total
    // "1" appears for active, with-runs, and with-findings — assert presence, not position
    expect(kpiValues.filter((v) => v === "1").length).toBeGreaterThanOrEqual(3);
  });

  it("opens the InvestigationDrawer when a target row is clicked", async () => {
    mockAll({ targets: [makeTarget()], executions: [], findings: [], assets: [] });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    await waitFor(() => {
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    });
  });

  it("shows validation executions matching the target's id in the drawer", async () => {
    mockAll({
      targets: [makeTarget()],
      executions: [
        makeExecution({ id: "exec-match", target_id: "target-1", status: "denied" }),
        makeExecution({ id: "exec-other", target_id: "some-other-target", status: "completed" }),
      ],
      findings: [],
      assets: [],
    });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    await waitFor(() => {
      expect(screen.getByText(/Validation Executions \(1\)/)).toBeInTheDocument();
    });
    // Only the matching execution's status should render, not the other
    // target's. StatusPill's uppercase styling is CSS-only — the real
    // DOM text content is lowercase.
    expect(screen.getAllByText("denied").length).toBeGreaterThan(0);
    expect(screen.queryByText("completed")).not.toBeInTheDocument();
  });

  it("shows findings matching the target's id in the drawer", async () => {
    mockAll({
      targets: [makeTarget()],
      executions: [],
      findings: [
        makeFinding({ id: "f-match", target_id: "target-1", severity: "critical" }),
        makeFinding({ id: "f-other", target_id: "some-other-target", severity: "low" }),
      ],
      assets: [],
    });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    await waitFor(() => {
      expect(screen.getByText(/Findings \(1\)/)).toBeInTheDocument();
    });
    expect(screen.getByText("critical")).toBeInTheDocument();
    expect(screen.queryByText("low")).not.toBeInTheDocument();
  });

  it("shows the canonical asset link only when associated_target_id resolves to a real asset", async () => {
    mockAll({
      targets: [makeTarget()],
      executions: [],
      findings: [],
      assets: [makeAsset({ associated_target_id: "target-1" })],
    });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    await waitFor(() => {
      expect(screen.getByText(/QA Test Target →/)).toBeInTheDocument();
    });
  });

  it("does not show a canonical asset link when no asset resolves to this target", async () => {
    mockAll({
      targets: [makeTarget()],
      executions: [],
      findings: [],
      assets: [makeAsset({ associated_target_id: "some-other-target" })],
    });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    await waitFor(() => {
      expect(screen.getByText("Not yet resolved to a canonical asset")).toBeInTheDocument();
    });
  });

  // Regression test: an earlier draft of this page linked to
  // `/assets?highlight=${asset.id}` — a query param `/assets/page.tsx`
  // never reads (confirmed via source inspection), which would have
  // silently done nothing. The canonical asset link must be a plain
  // `/assets` href, never a fabricated deep-link param.
  it("never emits a fabricated ?highlight= query param on the canonical asset link", async () => {
    mockAll({
      targets: [makeTarget()],
      executions: [],
      findings: [],
      assets: [makeAsset({ id: "asset-99", associated_target_id: "target-1" })],
    });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    const assetLink = await screen.findByText(/QA Test Target →/);
    expect(assetLink.closest("a")).toHaveAttribute("href", "/assets");
  });

  it("renders honest empty states when a target has no executions or findings", async () => {
    mockAll({ targets: [makeTarget()], executions: [], findings: [], assets: [] });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    await waitFor(() => {
      expect(screen.getByText("No validation runs yet.")).toBeInTheDocument();
    });
    expect(screen.getByText("No findings for this target.")).toBeInTheDocument();
  });

  it("cross-navigates to the real, existing /validation-operations route", async () => {
    mockAll({
      targets: [makeTarget()],
      executions: [makeExecution()],
      findings: [],
      assets: [],
    });
    render(<TargetsPage />);

    await waitFor(() => expect(screen.getByText("QA Test Target")).toBeInTheDocument());
    fireEvent.click(screen.getByText("QA Test Target"));

    const link = await screen.findByText("View in Validation Operations →");
    expect(link.closest("a")).toHaveAttribute("href", "/validation-operations");
  });

  describe("Register Target form accessibility", () => {
    it("every field has a real programmatic label, not a placeholder-only name", async () => {
      mockAll({ targets: [], executions: [], findings: [], assets: [] });
      const { container } = render(<TargetsPage />);
      fireEvent.click(await screen.findByText("Register Target"));

      for (const name of ["Target name", "Description", "Target type", "Provider", "Endpoint URL"]) {
        const field = screen.getByLabelText(name, { exact: false });
        expect(field.id).toBeTruthy();
        expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
      }
    });

    it("required fields expose aria-required, and the endpoint field uses type=url", async () => {
      mockAll({ targets: [], executions: [], findings: [], assets: [] });
      render(<TargetsPage />);
      fireEvent.click(await screen.findByText("Register Target"));

      expect(screen.getByLabelText("Target name", { exact: false })).toHaveAttribute("aria-required", "true");
      expect(screen.getByLabelText("Description", { exact: false })).not.toHaveAttribute("aria-required");
      const endpoint = screen.getByLabelText("Endpoint URL", { exact: false });
      expect(endpoint).toHaveAttribute("aria-required", "true");
      expect(endpoint).toHaveAttribute("type", "url");
    });

    it("no duplicate field ids exist in the registration form", async () => {
      mockAll({ targets: [], executions: [], findings: [], assets: [] });
      const { container } = render(<TargetsPage />);
      fireEvent.click(await screen.findByText("Register Target"));

      const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("submitting valid input sends the exact unchanged payload", async () => {
      mockAll({ targets: [], executions: [], findings: [], assets: [] });
      const created = makeTarget({ id: "new-target" });
      vi.mocked(api.post).mockResolvedValue(created);
      render(<TargetsPage />);
      fireEvent.click(await screen.findByText("Register Target"));

      fireEvent.change(screen.getByLabelText("Target name", { exact: false }), {
        target: { value: "New Target" },
      });
      fireEvent.change(screen.getByLabelText("Endpoint URL", { exact: false }), {
        target: { value: "https://api.example.com/v1" },
      });
      fireEvent.click(screen.getByText("Register Target", { selector: "button[type=submit]" }));

      await waitFor(() => {
        expect(api.post).toHaveBeenCalledWith("/api/v1/targets", {
          name: "New Target",
          description: "",
          target_type: "llm_application",
          provider: "openai",
          endpoint: "https://api.example.com/v1",
        });
      });
    });

    it("a failed submission shows a role=alert error, distinct from field validation", async () => {
      mockAll({ targets: [], executions: [], findings: [], assets: [] });
      vi.mocked(api.post).mockRejectedValue(new Error("Server unavailable"));
      render(<TargetsPage />);
      fireEvent.click(await screen.findByText("Register Target"));

      fireEvent.change(screen.getByLabelText("Target name", { exact: false }), {
        target: { value: "New Target" },
      });
      fireEvent.change(screen.getByLabelText("Endpoint URL", { exact: false }), {
        target: { value: "https://api.example.com/v1" },
      });
      fireEvent.click(screen.getByText("Register Target", { selector: "button[type=submit]" }));

      await waitFor(() => {
        expect(screen.getByRole("alert")).toHaveTextContent("Server unavailable");
      });
    });
  });
});
