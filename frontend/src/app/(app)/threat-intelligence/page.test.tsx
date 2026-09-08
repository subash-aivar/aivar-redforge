import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import ThreatIntelligenceOverviewPage from "./page";
import { ApiError } from "@/lib/api";
import type { PaginatedIocList } from "@/lib/iocIntelligence";

vi.mock("@/lib/auth", () => ({
  getMe: vi.fn().mockResolvedValue({ user_id: "user-1", email: "analyst@example.com" }),
}));

const effectiveAccessMock = vi.fn();
vi.mock("@/lib/rbac", () => ({
  getEffectiveAccess: () => effectiveAccessMock(),
}));

const listTenantIocsMock = vi.fn();
vi.mock("@/lib/iocIntelligence", async () => {
  const actual = await vi.importActual<typeof import("@/lib/iocIntelligence")>(
    "@/lib/iocIntelligence",
  );
  return { ...actual, listTenantIocs: (...args: unknown[]) => listTenantIocsMock(...args) };
});

function listOf(count: number, items: PaginatedIocList["items"] = []): PaginatedIocList {
  return { items, count, total: count, limit: items.length || 1, offset: 0 };
}

const summary = {
  ioc_id: "ioc-1",
  tenant_id: "org-1",
  ioc_type: "ip",
  canonical_key: "1.2.3.4",
  lifecycle: "active",
  epistemic_state: "confirmed",
  created_at: "2026-08-01T00:00:00Z",
  updated_at: "2026-08-01T00:00:00Z",
  valid_until: null,
  source_count: 1,
  evidence_count: 1,
};

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("ThreatIntelligenceOverviewPage", () => {
  it("renders real IOC counts from the API — never a fabricated number", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: ["ioc_intel:read"] });
    listTenantIocsMock.mockImplementation((filters: { lifecycle?: string; limit?: number }) => {
      if (filters?.lifecycle === "active") return Promise.resolve(listOf(3, [summary]));
      if (filters?.limit === 5) return Promise.resolve(listOf(42, [summary]));
      return Promise.resolve(listOf(42));
    });
    render(<ThreatIntelligenceOverviewPage />);
    await waitFor(() => expect(screen.getByText("42")).toBeInTheDocument());
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("shows a real permission-denied state, not a zero count, when the backend returns 403", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: [] });
    listTenantIocsMock.mockRejectedValue(new ApiError(403, "FORBIDDEN", "forbidden"));
    render(<ThreatIntelligenceOverviewPage />);
    await waitFor(() => expect(screen.getByText(/permission/i)).toBeInTheDocument());
    expect(screen.queryByText("0")).not.toBeInTheDocument();
  });

  it("shows an honest empty state when there are genuinely zero IOCs", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: ["ioc_intel:read"] });
    listTenantIocsMock.mockResolvedValue(listOf(0));
    render(<ThreatIntelligenceOverviewPage />);
    await waitFor(() => expect(screen.getByText("No IOCs observed yet.")).toBeInTheDocument());
  });

  it("lists all nine capabilities with honest planned/live status, and flags missing access", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: ["ioc_intel:read"] });
    listTenantIocsMock.mockResolvedValue(listOf(0));
    render(<ThreatIntelligenceOverviewPage />);
    await waitFor(() => expect(screen.getAllByText("Planned").length).toBe(8));
    expect(screen.getByText("Threat Actors")).toBeInTheDocument();
    expect(screen.getByText("Relationships")).toBeInTheDocument();
    // lacks threat_intel:read -> Threat Actors card shows the honest hint
    expect(screen.getAllByText("No read access").length).toBe(8);
  });

  it("never issues an unbounded client-side scan — every IOC call is limit-bounded", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: ["ioc_intel:read"] });
    listTenantIocsMock.mockResolvedValue(listOf(0));
    render(<ThreatIntelligenceOverviewPage />);
    await waitFor(() => expect(listTenantIocsMock).toHaveBeenCalled());
    for (const call of listTenantIocsMock.mock.calls) {
      const filters = call[0] as { limit?: number } | undefined;
      expect(filters?.limit).toBeDefined();
      expect(filters!.limit!).toBeLessThanOrEqual(5);
    }
  });
});
