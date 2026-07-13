import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as securityOperations from "@/lib/securityOperations";
import ExecutionTelemetryDetailPage from "./page";
import type { ExecutionTelemetryDetail } from "@/lib/securityOperations";

vi.mock("next/navigation", () => ({
  useParams: () => ({ id: "exec-1" }),
}));

vi.mock("@/lib/securityOperations", async () => {
  const actual = await vi.importActual<typeof import("@/lib/securityOperations")>(
    "@/lib/securityOperations"
  );
  return { ...actual, getExecutionDetail: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function makeDetail(overrides: Partial<ExecutionTelemetryDetail> = {}): ExecutionTelemetryDetail {
  return {
    summary: {
      id: "exec-1",
      organization_id: "org-1",
      target_id: "api.example.internal",
      trigger: "manual",
      continuous_policy_id: null,
      profile: "safe_active_baseline_v1",
      state: "completed",
      phase: "completed",
      latest_event_title: "execution_completed",
      created_at: new Date(0).toISOString(),
      started_at: new Date(0).toISOString(),
      completed_at: new Date(1000).toISOString(),
    },
    timeline: [
      {
        phase: "authorization",
        event_type: "execution_created",
        title: "execution created",
        occurred_at: new Date(0).toISOString(),
      },
    ],
    result_summary: "3 services validated. 1 condition observed.",
    ...overrides,
  };
}

describe("ExecutionTelemetryDetailPage", () => {
  it("renders the backend-derived phase, not a fabricated percentage", async () => {
    vi.mocked(securityOperations.getExecutionDetail).mockResolvedValue(makeDetail());
    render(<ExecutionTelemetryDetailPage />);
    await waitFor(() => {
      expect(screen.getByTestId("current-phase")).toHaveTextContent("Completed");
    });
    expect(screen.queryByText(/%/)).not.toBeInTheDocument();
  });

  it("renders the crisp backend result summary verbatim", async () => {
    vi.mocked(securityOperations.getExecutionDetail).mockResolvedValue(makeDetail());
    render(<ExecutionTelemetryDetailPage />);
    await waitFor(() => {
      expect(
        screen.getByText("3 services validated. 1 condition observed.")
      ).toBeInTheDocument();
    });
  });

  it("renders the full timeline, not just the latest event", async () => {
    vi.mocked(securityOperations.getExecutionDetail).mockResolvedValue(
      makeDetail({
        timeline: [
          {
            phase: "authorization",
            event_type: "execution_created",
            title: "execution created",
            occurred_at: new Date(0).toISOString(),
          },
          {
            phase: "completed",
            event_type: "execution_completed",
            title: "execution completed",
            occurred_at: new Date(1000).toISOString(),
          },
        ],
      })
    );
    render(<ExecutionTelemetryDetailPage />);
    await waitFor(() => {
      expect(screen.getByText("execution created")).toBeInTheDocument();
      expect(screen.getByText("execution completed")).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(securityOperations.getExecutionDetail).mockRejectedValue(
      new Error("execution not found")
    );
    render(<ExecutionTelemetryDetailPage />);
    await waitFor(() => {
      expect(screen.getByText(/UNAVAILABLE|execution not found/i)).toBeInTheDocument();
    });
  });
});
