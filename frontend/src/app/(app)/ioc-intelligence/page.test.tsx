import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent, within } from "@testing-library/react";

vi.mock("@/lib/iocIntelligence", async () => {
  const actual = await vi.importActual<typeof import("@/lib/iocIntelligence")>(
    "@/lib/iocIntelligence"
  );
  return {
    ...actual,
    listTenantIocs: vi.fn(),
    listGlobalIocs: vi.fn(),
    getIoc: vi.fn(),
    observeTenantIoc: vi.fn(),
    observeGlobalIoc: vi.fn(),
    addSourceAttribution: vi.fn(),
    addEvidenceCitation: vi.fn(),
    transitionLifecycle: vi.fn(),
    transitionEpistemicState: vi.fn(),
    disputeIoc: vi.fn(),
    refuteIoc: vi.fn(),
    refreshIoc: vi.fn(),
    supersedeIoc: vi.fn(),
    revokeIoc: vi.fn(),
  };
});

vi.mock("@/lib/auth", () => ({
  getMe: vi.fn().mockResolvedValue({ user_id: "user-1", email: "analyst@example.com" }),
}));

vi.mock("@/lib/rbac", () => ({
  getEffectiveAccess: vi.fn().mockResolvedValue({
    effective_permissions: ["ioc_intel:read", "ioc_intel:observe", "ioc_intel:manage"],
  }),
}));

vi.mock("@/lib/platform", () => ({
  getPlatformAccess: vi.fn().mockResolvedValue({
    user_id: "user-1",
    platform_roles: [],
    permissions: [],
    has_platform_access: false,
  }),
}));

import * as ioc from "@/lib/iocIntelligence";
import * as platformLib from "@/lib/platform";
import { ApiError } from "@/lib/api";
import IocIntelligencePage from "./page";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

function tenantSummary(overrides: Partial<ioc.IocSummary> = {}): ioc.IocSummary {
  return {
    ioc_id: "ioc-1",
    tenant_id: "org-1",
    ioc_type: "ip",
    canonical_key: "ip:1.2.3.4",
    lifecycle: "active",
    epistemic_state: "observation",
    created_at: "2026-08-05T00:00:00Z",
    updated_at: "2026-08-05T00:00:00Z",
    valid_until: null,
    source_count: 1,
    evidence_count: 0,
    ...overrides,
  };
}

function detailFor(summary: ioc.IocSummary): ioc.IocDetail {
  return {
    ...summary,
    valid_from: "2026-08-05T00:00:00Z",
    source_attributions: [
      {
        source_system: "alienvault_otx",
        external_id: "pulse-1",
        content_hash: null,
        observed_at: "2026-08-05T00:00:00Z",
        weight_applied: 0.9,
        confidence: "high",
      },
    ],
    evidence_citations: [],
  };
}

describe("IocIntelligencePage", () => {
  it("renders IOC rows from a real API response", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [tenantSummary()],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    render(<IocIntelligencePage />);
    await waitFor(() => expect(screen.getByText("ip:1.2.3.4")).toBeInTheDocument());
    expect(ioc.listTenantIocs).toHaveBeenCalled();
  });

  it("shows an honest empty state for tenant scope with no records", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    render(<IocIntelligencePage />);
    await waitFor(() =>
      expect(screen.getByText("No tenant IOC intelligence recorded yet.")).toBeInTheDocument()
    );
  });

  it("shows an honest empty state for global scope with no records", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    vi.mocked(ioc.listGlobalIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    vi.mocked(platformLib.getPlatformAccess).mockResolvedValue({
      user_id: "user-1",
      platform_roles: ["platform_security_admin"],
      permissions: ["platform:ioc_intel:read", "platform:ioc_intel:manage"],
      has_platform_access: true,
    });
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("Global Scope"));
    await waitFor(() =>
      expect(screen.getByText("No global IOC intelligence available.")).toBeInTheDocument()
    );
  });

  it("renders tenant and global scope visibly distinct via the scope column", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [tenantSummary({ tenant_id: "org-1" })],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    render(<IocIntelligencePage />);
    await waitFor(() => expect(screen.getByText("ip:1.2.3.4")).toBeInTheDocument());
    // scope pill renders as StatusPill("active") for tenant-owned rows
    const row = screen.getByText("ip:1.2.3.4").closest("tr")!;
    expect(within(row).getByText("active")).toBeInTheDocument();
  });

  it("serializes filters into the list request", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    render(<IocIntelligencePage />);
    await waitFor(() => expect(ioc.listTenantIocs).toHaveBeenCalled());
    fireEvent.change(screen.getByLabelText("Lifecycle filter"), { target: { value: "revoked" } });
    await waitFor(() =>
      expect(ioc.listTenantIocs).toHaveBeenLastCalledWith(
        expect.objectContaining({ lifecycle: "revoked", limit: 25, offset: 0 })
      )
    );
  });

  it("bounds pagination to the configured page size", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    render(<IocIntelligencePage />);
    await waitFor(() =>
      expect(ioc.listTenantIocs).toHaveBeenCalledWith(expect.objectContaining({ limit: 25 }))
    );
  });

  it("opens the detail drawer on row click and renders source attributions from the real DTO shape", async () => {
    const summary = tenantSummary();
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    await waitFor(() => expect(screen.getByText(/pulse-1/)).toBeInTheDocument());
    expect(screen.getByText(/alienvault_otx/)).toBeInTheDocument();
  });

  it("renders an honest 'no evidence' message when evidence_citations is empty", async () => {
    const summary = tenantSummary();
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    await waitFor(() =>
      expect(screen.getByText("No tenant evidence citation recorded yet.")).toBeInTheDocument()
    );
  });

  it("renders lifecycle and epistemic state as visibly separate fields", async () => {
    const summary = tenantSummary({ lifecycle: "superseded", epistemic_state: "corroborated" });
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    await waitFor(() =>
      expect(screen.getByText("Lifecycle (operational relevance)")).toBeInTheDocument()
    );
    expect(screen.getByText("Epistemic State (trust)")).toBeInTheDocument();
    expect(screen.getAllByText("superseded").length).toBeGreaterThan(0);
    expect(screen.getAllByText("corroborated").length).toBeGreaterThan(0);
  });

  it("renders ErrorState-equivalent on API failure without swallowing it", async () => {
    vi.mocked(ioc.listTenantIocs).mockRejectedValue(new ApiError(500, "internal", "Server error"));
    render(<IocIntelligencePage />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Server error"));
  });

  it("does not show the global observation action for an ordinary organization member", async () => {
    vi.mocked(platformLib.getPlatformAccess).mockResolvedValue({
      user_id: "user-1",
      platform_roles: [],
      permissions: [],
      has_platform_access: false,
    });
    vi.mocked(ioc.listGlobalIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("Global Scope"));
    await waitFor(() =>
      expect(
        screen.getByText(/don't have platform authority to view global IOC intelligence/)
      ).toBeInTheDocument()
    );
    expect(screen.queryByText("+ Observe Global IOC")).not.toBeInTheDocument();
  });

  it("shows the global observation action for a platform-authorized principal", async () => {
    vi.mocked(platformLib.getPlatformAccess).mockResolvedValue({
      user_id: "user-1",
      platform_roles: ["platform_security_admin"],
      permissions: ["platform:ioc_intel:read", "platform:ioc_intel:manage"],
      has_platform_access: true,
    });
    vi.mocked(ioc.listGlobalIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("Global Scope"));
    await waitFor(() => expect(screen.getByText("+ Observe Global IOC")).toBeInTheDocument());
  });

  it("submits a tenant observation with no tenant_id in the request body", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    vi.mocked(ioc.observeTenantIoc).mockResolvedValue(detailFor(tenantSummary()));
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("+ Observe Tenant IOC"));
    fireEvent.change(screen.getByLabelText("Indicator Value", { exact: false }), {
      target: { value: "5.5.5.5" },
    });
    fireEvent.click(screen.getByText("Observe"));
    await waitFor(() => expect(ioc.observeTenantIoc).toHaveBeenCalled());
    const body = vi.mocked(ioc.observeTenantIoc).mock.calls[0][0] as unknown as Record<
      string,
      unknown
    >;
    expect(body).not.toHaveProperty("tenant_id");
  });

  it("emits no X-Roles header anywhere in the API client module", async () => {
    const { readFileSync } = await import("node:fs");
    const path = await import("node:path");
    const source = readFileSync(
      path.resolve(process.cwd(), "src/lib/iocIntelligence.ts"),
      "utf8"
    );
    expect(source.toLowerCase()).not.toContain("x-roles");
  });

  it("cancel on the observation form sends no request", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({ items: [], count: 0, total: 0, limit: 25, offset: 0 });
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("+ Observe Tenant IOC"));
    fireEvent.click(screen.getByText("Cancel"));
    expect(ioc.observeTenantIoc).not.toHaveBeenCalled();
  });

  it("surfaces mutation errors with role=alert, and gives a specific message + reloads on a 409 conflict", async () => {
    const summary = tenantSummary();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    vi.mocked(ioc.revokeIoc).mockRejectedValue(
      new ApiError(409, "conflict", "Optimistic lock conflict")
    );
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    fireEvent.click(await screen.findByText("Revoke"));
    expect(confirmSpy).toHaveBeenCalled();
    await waitFor(() =>
      expect(screen.getByText(/changed by someone else/)).toBeInTheDocument()
    );
    expect(screen.getByText(/changed by someone else/).closest('[role="alert"]')).toBeTruthy();
    // Stale detail is re-fetched after the conflict, not left showing
    // the pre-conflict snapshot.
    await waitFor(() => expect(ioc.getIoc).toHaveBeenCalledTimes(2));
    confirmSpy.mockRestore();
  });

  it("shows the backend's own message for a domain-rule 409 (e.g. invalid transition) instead of the generic conflict message, and does not reload", async () => {
    // The backend maps several distinct rejections to 409, not just
    // optimistic-lock conflicts (InvalidEpistemicStateTransitionError,
    // InvalidLifecycleTransitionError, DuplicateSourceAttributionError,
    // IocIntelIntegrityError all use status 409 too). Only a message
    // that actually says "Optimistic lock conflict" should trigger the
    // "someone else changed this" wording and an auto-reload — anything
    // else must show the backend's own specific message unmodified.
    const summary = tenantSummary();
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    vi.mocked(ioc.disputeIoc).mockRejectedValue(
      new ApiError(409, "conflict", "Invalid epistemic-state transition evidence -> disputed")
    );
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    fireEvent.click(await screen.findByText("Dispute"));
    await waitFor(() =>
      expect(
        screen.getByText("Invalid epistemic-state transition evidence -> disputed")
      ).toBeInTheDocument()
    );
    expect(screen.queryByText(/changed by someone else/)).not.toBeInTheDocument();
    // No reload — getIoc was called once for the initial drawer open only.
    expect(ioc.getIoc).toHaveBeenCalledTimes(1);
  });

  it("does not mutate when the Revoke confirmation is declined", async () => {
    const summary = tenantSummary();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    fireEvent.click(await screen.findByText("Revoke"));
    expect(confirmSpy).toHaveBeenCalled();
    expect(ioc.revokeIoc).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it("does not mutate when the Supersede confirmation is declined", async () => {
    const summary = tenantSummary();
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [summary],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    vi.mocked(ioc.getIoc).mockResolvedValue(detailFor(summary));
    render(<IocIntelligencePage />);
    fireEvent.click(await screen.findByText("ip:1.2.3.4"));
    fireEvent.click(await screen.findByText("Supersede"));
    expect(confirmSpy).toHaveBeenCalled();
    expect(ioc.supersedeIoc).not.toHaveBeenCalled();
    confirmSpy.mockRestore();
  });

  it("renders the real server-side total across the entire filtered dataset, not just the page size", async () => {
    // M51.2 Slice 2.1: `total` is now a real, server-computed count
    // across the whole matching dataset — deliberately different from
    // `count` (this page's size) here, to prove the KPI reads `total`
    // and does not silently fall back to page size.
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [tenantSummary()],
      count: 1,
      total: 47,
      limit: 25,
      offset: 0,
    });
    render(<IocIntelligencePage />);
    await waitFor(() => expect(screen.getByText("Total Matching Results")).toBeInTheDocument());
    expect(screen.getByText("47")).toBeInTheDocument();
    expect(screen.getByText("Entire filtered dataset")).toBeInTheDocument();
  });

  it("sends search, type, validity, and sort as real server-side query parameters", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [tenantSummary()],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    render(<IocIntelligencePage />);
    await waitFor(() => expect(ioc.listTenantIocs).toHaveBeenCalled());

    fireEvent.change(screen.getByPlaceholderText("Search the entire dataset by indicator value…"), {
      target: { value: "198.51.100" },
    });
    fireEvent.change(screen.getByLabelText("Type filter"), { target: { value: "domain" } });
    fireEvent.change(screen.getByLabelText("Validity filter"), { target: { value: "lapsed" } });
    fireEvent.change(screen.getByLabelText("Sort by filter"), { target: { value: "valid_until" } });

    await waitFor(() => {
      const lastCall = vi.mocked(ioc.listTenantIocs).mock.calls.at(-1)?.[0];
      expect(lastCall).toMatchObject({
        search: "198.51.100",
        ioc_type: "domain",
        validity: "lapsed",
        sort_by: "valid_until",
      });
    });
  });

  it("shows Reset filters only once a filter is active, and clears every filter on click", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [tenantSummary()],
      count: 1,
      total: 1,
      limit: 25,
      offset: 0,
    });
    render(<IocIntelligencePage />);
    await waitFor(() => expect(ioc.listTenantIocs).toHaveBeenCalled());
    expect(screen.queryByText("Reset filters")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Type filter"), { target: { value: "domain" } });
    await waitFor(() => expect(screen.getByText("Reset filters")).toBeInTheDocument());

    fireEvent.click(screen.getByText("Reset filters"));
    await waitFor(() => expect(screen.queryByText("Reset filters")).not.toBeInTheDocument());
    const lastCall = vi.mocked(ioc.listTenantIocs).mock.calls.at(-1)?.[0];
    expect(lastCall).toMatchObject({ ioc_type: undefined, search: undefined });
  });

  it("shows an honest empty-filtered-state message distinct from the true-empty message", async () => {
    vi.mocked(ioc.listTenantIocs).mockResolvedValue({
      items: [],
      count: 0,
      total: 0,
      limit: 25,
      offset: 0,
    });
    render(<IocIntelligencePage />);
    await waitFor(() =>
      expect(screen.getByText("No tenant IOC intelligence recorded yet.")).toBeInTheDocument()
    );

    fireEvent.change(screen.getByLabelText("Type filter"), { target: { value: "domain" } });
    await waitFor(() =>
      expect(
        screen.getByText("No IOCs match the current search/filters — try Reset filters.")
      ).toBeInTheDocument()
    );
  });
});
