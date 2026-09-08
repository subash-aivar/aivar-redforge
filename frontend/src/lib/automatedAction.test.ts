import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/lib/api";
import {
  listExecutions,
  getExecution,
  cancelExecution,
  authorizeEscalation,
  requestRollback,
} from "@/lib/automatedAction";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, get: vi.fn(), post: vi.fn() } };
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("automatedAction client — verified against real backend routes", () => {
  // Regression test for a real bug found in browser QA: this client
  // previously called `/api/v1/automated-action/*`, but the backend
  // router (`automated_action/api/v1/routes.py`) has no path prefix —
  // real paths are `/api/v1/executions*`, confirmed via live curl
  // (old paths 404'd, real paths exist).
  it("calls the real /api/v1/executions path, not /api/v1/automated-action/executions", async () => {
    vi.mocked(api.get).mockResolvedValue([]);
    await listExecutions();
    expect(api.get).toHaveBeenCalledWith("/api/v1/executions");
  });

  it("calls the real per-execution path for getExecution", async () => {
    vi.mocked(api.get).mockResolvedValue({});
    await getExecution("exec-1");
    expect(api.get).toHaveBeenCalledWith("/api/v1/executions/exec-1");
  });

  it("calls the real cancel path", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await cancelExecution("exec-1", "test");
    expect(api.post).toHaveBeenCalledWith("/api/v1/executions/exec-1/cancel", {
      cancelled_by: "ui",
      reason: "test",
    });
  });

  // Regression test: the real authorize-step/rollback endpoints are
  // nested under the execution id (`/executions/{execution_id}/...`),
  // which the old signature had no way to supply.
  it("requires an executionId for authorizeEscalation (real route is execution-scoped)", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await authorizeEscalation("exec-1", "esc-1", "notes");
    expect(api.post).toHaveBeenCalledWith("/api/v1/executions/exec-1/authorize-step", {
      escalation_id: "esc-1",
      authorizer_id: "ui",
      notes: "notes",
    });
  });

  it("requires an executionId for requestRollback (real route is execution-scoped)", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await requestRollback("exec-1", "record-1");
    expect(api.post).toHaveBeenCalledWith("/api/v1/executions/exec-1/rollback", {
      record_id: "record-1",
      initiated_by: "ui",
    });
  });
});
