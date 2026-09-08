import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { api } from "@/lib/api";
import ContinuousValidationPage from "./page";
import type { ContinuousValidationPolicy, SecurityDriftEvent } from "@/lib/continuousValidation";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function makePolicy(overrides: Partial<ContinuousValidationPolicy> = {}): ContinuousValidationPolicy {
  return {
    id: "policy-1",
    organization_id: "org-1",
    target_id: "target-1",
    requester_user_id: "user-1",
    profile: "safe_active_baseline_v1",
    cadence: "hourly",
    lifecycle: "active",
    next_due_at: new Date(1000).toISOString(),
    last_scheduled_at: new Date(500).toISOString(),
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function makeDriftEvent(overrides: Partial<SecurityDriftEvent> = {}): SecurityDriftEvent {
  return {
    id: "drift-1",
    organization_id: "org-1",
    continuous_policy_id: "policy-1",
    execution_id: "exec-1",
    category: "condition_appeared",
    identity_key: "cond:abc",
    summary: "Security condition appeared: cond:abc.",
    detail: {},
    detected_at: new Date(2000).toISOString(),
    ...overrides,
  };
}

function mockApi(opts: {
  policies?: ContinuousValidationPolicy[];
  changeFeed?: SecurityDriftEvent[];
  policyDrift?: SecurityDriftEvent[];
  targets?: Array<{ id: string; name: string; endpoint: string }>;
}) {
  const {
    policies = [makePolicy()],
    changeFeed = [makeDriftEvent()],
    policyDrift = [makeDriftEvent()],
    targets = [{ id: "target-1", name: "Owned Test Target", endpoint: "https://example.test/" }],
  } = opts;

  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.includes("/change-feed")) return Promise.resolve(changeFeed);
    if (path.match(/\/policies\/[^/]+\/drift/)) return Promise.resolve(policyDrift);
    if (path.match(/\/continuous-validation\/policies\/[^/]+$/)) {
      const id = path.split("/").pop()?.split("?")[0];
      const found = policies.find((p) => p.id === id) ?? policies[0];
      return Promise.resolve(found);
    }
    if (path.includes("/continuous-validation/policies")) return Promise.resolve(policies);
    if (path.includes("/api/v1/targets")) return Promise.resolve(targets);
    return Promise.reject(new Error(`unexpected path: ${path}`));
  });
}

describe("ContinuousValidationPage overview", () => {
  it("renders backend-derived policies, not fabricated", async () => {
    mockApi({ policies: [makePolicy({ cadence: "daily" })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => {
      expect(screen.getByText("DAILY")).toBeInTheDocument();
    });
  });

  it("renders an explicit empty state, not a blank list", async () => {
    mockApi({ policies: [] });
    render(<ContinuousValidationPage />);
    await waitFor(() => {
      expect(screen.getByText(/No continuous validation policies match/i)).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(api.get).mockRejectedValue(new Error("network down"));
    render(<ContinuousValidationPage />);
    await waitFor(() => {
      expect(screen.getByText(/UNAVAILABLE/i)).toBeInTheDocument();
    });
  });

  it("renders an unrecognized lifecycle as UNKNOWN, not a crash", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "some_future_state" as never })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => {
      expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    });
  });
});

describe("ContinuousValidationPage change feed", () => {
  it("renders drift events with crisp, non-story-prose category labels", async () => {
    mockApi({ changeFeed: [makeDriftEvent({ category: "condition_reactivated" })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => {
      expect(screen.getByText("Condition Reactivated")).toBeInTheDocument();
    });
  });

  it("shows an explicit empty state when no drift has ever been detected", async () => {
    mockApi({ changeFeed: [] });
    render(<ContinuousValidationPage />);
    await waitFor(() => {
      expect(screen.getByText(/No drift has been detected yet/i)).toBeInTheDocument();
    });
  });
});

describe("ContinuousValidationPage lifecycle actions", () => {
  it("shows Activate for a DRAFT policy, never Pause/Resume", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "draft", next_due_at: null })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("DRAFT"));
    fireEvent.click(screen.getByText("DRAFT"));
    await waitFor(() => {
      expect(screen.getByText("Activate")).toBeInTheDocument();
    });
    expect(screen.queryByText("Pause")).not.toBeInTheDocument();
    expect(screen.queryByText("Resume")).not.toBeInTheDocument();
  });

  it("shows Pause and Run Now for an ACTIVE policy", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "active" })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("ACTIVE"));
    fireEvent.click(screen.getByText("ACTIVE"));
    await waitFor(() => {
      expect(screen.getByText("Pause")).toBeInTheDocument();
    });
    expect(screen.getByText("Run Now")).toBeInTheDocument();
    expect(screen.queryByText("Activate")).not.toBeInTheDocument();
  });

  it("shows Resume for a PAUSED policy", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "paused" })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("PAUSED"));
    fireEvent.click(screen.getByText("PAUSED"));
    await waitFor(() => {
      expect(screen.getByText("Resume")).toBeInTheDocument();
    });
  });

  it("a DISABLED policy shows no reactivation control — terminal, matching backend invariant", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "disabled" })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("DISABLED"));
    fireEvent.click(screen.getByText("DISABLED"));
    await waitFor(() => {
      expect(screen.getByText(/terminal — create a new policy/i)).toBeInTheDocument();
    });
    expect(screen.queryByText("Activate")).not.toBeInTheDocument();
    expect(screen.queryByText("Resume")).not.toBeInTheDocument();
    expect(screen.queryByText("Disable")).not.toBeInTheDocument();
    expect(screen.queryByText("Run Now")).not.toBeInTheDocument();
  });

  it("Run Now posts to the run-now endpoint and shows the resulting execution", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "active" })] });
    vi.mocked(api.post).mockImplementation((path: string) => {
      if (path.includes("/run-now")) {
        return Promise.resolve({ execution_id: "exec-99", status: "completed", trigger: "on_demand" });
      }
      return Promise.reject(new Error(`unexpected post: ${path}`));
    });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("ACTIVE"));
    fireEvent.click(screen.getByText("ACTIVE"));
    await waitFor(() => screen.getByText("Run Now"));
    fireEvent.click(screen.getByText("Run Now"));
    await waitFor(() => {
      expect(screen.getByText(/exec-99/)).toBeInTheDocument();
    });
  });

  it("shows the policy's own drift feed inside the detail view", async () => {
    mockApi({
      policies: [makePolicy({ lifecycle: "active" })],
      policyDrift: [makeDriftEvent({ category: "port_became_reachable", identity_key: "port:22" })],
    });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("ACTIVE"));
    fireEvent.click(screen.getByText("ACTIVE"));
    await waitFor(() => {
      expect(screen.getByText("Port Became Reachable")).toBeInTheDocument();
    });
    expect(screen.getByText("port:22")).toBeInTheDocument();
  });
});

describe("ContinuousValidationPage policy detail dialog semantics", () => {
  it("opens as a labelled dialog and Escape closes it, returning focus to the trigger", async () => {
    mockApi({ policies: [makePolicy({ lifecycle: "active" })] });
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("ACTIVE"));
    const trigger = screen.getByText("ACTIVE").closest("button")!;
    trigger.focus();
    fireEvent.click(trigger);

    await waitFor(() => {
      expect(screen.getByRole("dialog", { name: "Continuous Validation Policy" })).toBeInTheDocument();
    });
    expect(screen.getByRole("dialog")).toHaveAttribute("aria-modal", "true");

    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});

describe("ContinuousValidationPage create form", () => {
  it("requires a canonical target before submission", async () => {
    mockApi({});
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("New Policy"));
    fireEvent.click(screen.getByText("New Policy"));
    await waitFor(() => screen.getByText("Create Policy"));
    fireEvent.click(screen.getByText("Create Policy"));
    await waitFor(() => {
      expect(screen.getByText(/Select a canonical target/i)).toBeInTheDocument();
    });
  });

  it("never offers a free-text cron field — cadence is a closed dropdown", async () => {
    mockApi({});
    render(<ContinuousValidationPage />);
    await waitFor(() => screen.getByText("New Policy"));
    fireEvent.click(screen.getByText("New Policy"));
    await waitFor(() => screen.getByText("Cadence"));
    expect(screen.queryByLabelText(/cron/i)).not.toBeInTheDocument();
    expect(screen.getByText("Hourly")).toBeInTheDocument();
    expect(screen.getByText("Weekly")).toBeInTheDocument();
  });
});
