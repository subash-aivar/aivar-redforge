import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as securityOperations from "@/lib/securityOperations";
import SecurityOperationsPage from "./page";
import type {
  ExecutionTelemetrySummary,
  OperationalEvent,
  RuntimeComponent,
  SecurityOperationsSummary,
} from "@/lib/securityOperations";

vi.mock("@/lib/securityOperations", async () => {
  const actual = await vi.importActual<typeof import("@/lib/securityOperations")>(
    "@/lib/securityOperations"
  );
  return {
    ...actual,
    getSummary: vi.fn(),
    listChanges: vi.fn(),
    listExecutions: vi.fn(),
    listRuntimeComponents: vi.fn(),
  };
});

vi.mock("@/lib/useSecurityOperationsStream", () => ({
  useSecurityOperationsStream: vi.fn(() => ({
    connectionState: "connected",
    events: [],
    lastEventReceivedAt: null,
  })),
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function makeSummary(overrides: Partial<SecurityOperationsSummary> = {}): SecurityOperationsSummary {
  return {
    period: "24h",
    active_targets: 3,
    canonical_assets: 5,
    active_continuous_validation_policies: 2,
    validations_running: 1,
    validations_blocked_in_period: 0,
    validations_failed_in_period: 0,
    critical_high_conditions: 4,
    active_correlations: 1,
    drift_events_in_period: 2,
    runtime_unhealthy_components: 0,
    ...overrides,
  };
}

function makeEvent(overrides: Partial<OperationalEvent> = {}): OperationalEvent {
  return {
    cursor: "2026-01-01T00:00:00.000000|E|row-1",
    event_id: "e1",
    organization_id: "org-1",
    source_domain: "validation",
    importance: "warning",
    title: "Validation blocked: authorization denied",
    summary: "Authorization denied (no_authorization).",
    entity_type: "validation_execution",
    entity_id: "exec-1",
    occurred_at: new Date(0).toISOString(),
    schema_version: 1,
    ...overrides,
  };
}

function makeExecution(
  overrides: Partial<ExecutionTelemetrySummary> = {}
): ExecutionTelemetrySummary {
  return {
    id: "exec-1",
    organization_id: "org-1",
    target_id: "api.example.internal",
    trigger: "manual",
    continuous_policy_id: null,
    profile: "safe_active_baseline_v1",
    state: "running",
    phase: "service_validation",
    latest_event_title: "step_started",
    created_at: new Date(0).toISOString(),
    started_at: new Date(0).toISOString(),
    completed_at: null,
    ...overrides,
  };
}

function makeRuntimeComponent(overrides: Partial<RuntimeComponent> = {}): RuntimeComponent {
  return {
    component_id: "database",
    status: "healthy",
    message: "",
    checked_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function mockClients(opts: {
  summary?: SecurityOperationsSummary;
  changes?: OperationalEvent[];
  executions?: ExecutionTelemetrySummary[];
  runtime?: RuntimeComponent[];
}) {
  const {
    summary = makeSummary(),
    changes = [makeEvent()],
    executions = [makeExecution()],
    runtime = [makeRuntimeComponent()],
  } = opts;
  vi.mocked(securityOperations.getSummary).mockResolvedValue(summary);
  vi.mocked(securityOperations.listChanges).mockResolvedValue(changes);
  vi.mocked(securityOperations.listExecutions).mockResolvedValue(executions);
  vi.mocked(securityOperations.listRuntimeComponents).mockResolvedValue(runtime);
}

describe("SecurityOperationsPage summary", () => {
  it("renders backend-derived summary counts, not fabricated", async () => {
    mockClients({ summary: makeSummary({ active_targets: 7 }) });
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText("7")).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(securityOperations.getSummary).mockRejectedValue(new Error("network down"));
    vi.mocked(securityOperations.listChanges).mockRejectedValue(new Error("network down"));
    vi.mocked(securityOperations.listExecutions).mockRejectedValue(new Error("network down"));
    vi.mocked(securityOperations.listRuntimeComponents).mockRejectedValue(
      new Error("network down")
    );
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText(/UNAVAILABLE|network down/i)).toBeInTheDocument();
    });
  });
});

describe("SecurityOperationsPage change feed", () => {
  it("renders an explicit empty state, not a blank list", async () => {
    mockClients({ changes: [] });
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No changes in this period/i)).toBeInTheDocument();
    });
  });

  it("renders crisp backend-provided titles verbatim", async () => {
    mockClients({ changes: [makeEvent({ title: "443/tcp became reachable" })] });
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText("443/tcp became reachable")).toBeInTheDocument();
    });
  });
});

describe("SecurityOperationsPage active executions", () => {
  it("renders an explicit empty state, not a blank list", async () => {
    mockClients({ executions: [] });
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No recent executions/i)).toBeInTheDocument();
    });
  });

  it("links each execution row to its telemetry detail page", async () => {
    mockClients({ executions: [makeExecution({ id: "exec-42" })] });
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      const link = screen.getByRole("link", { name: /api.example.internal/i });
      expect(link).toHaveAttribute("href", "/security-operations/executions/exec-42");
    });
  });
});

describe("SecurityOperationsPage runtime components", () => {
  it("renders an unrecognized runtime status as a safe fallback, not a crash", async () => {
    mockClients({
      runtime: [makeRuntimeComponent({ status: "some_future_status" as never })],
    });
    render(<SecurityOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText("database")).toBeInTheDocument();
    });
  });
});
