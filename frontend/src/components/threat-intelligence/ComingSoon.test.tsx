import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import { ComingSoon } from "./ComingSoon";
import { THREAT_INTEL_CAPABILITIES } from "@/lib/threatIntelShell";

vi.mock("@/lib/auth", () => ({
  getMe: vi.fn().mockResolvedValue({ user_id: "user-1", email: "analyst@example.com" }),
}));

const effectiveAccessMock = vi.fn();
vi.mock("@/lib/rbac", () => ({
  getEffectiveAccess: () => effectiveAccessMock(),
}));

const capability = THREAT_INTEL_CAPABILITIES.find((c) => c.key === "malware")!;

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("ComingSoon", () => {
  it("shows a permission-denied state for a user without the capability's read permission", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: ["ioc_intel:read"] });
    render(<ComingSoon capability={capability} />);
    await waitFor(() => expect(screen.getByText(/permission/i)).toBeInTheDocument());
    expect(screen.queryByText(/Backend Certified/)).not.toBeInTheDocument();
  });

  it("shows an honest not-yet-built state — never fabricated data — for a user with read access", async () => {
    effectiveAccessMock.mockResolvedValue({
      effective_permissions: [capability.tenantReadPerm],
    });
    render(<ComingSoon capability={capability} />);
    await waitFor(() => expect(screen.getByText(/Backend Certified/)).toBeInTheDocument());
    expect(screen.getByText(/not yet include an operator interface/)).toBeInTheDocument();
  });

  it("names the specific capability in the honest placeholder text", async () => {
    effectiveAccessMock.mockResolvedValue({
      effective_permissions: [capability.tenantReadPerm],
    });
    render(<ComingSoon capability={capability} />);
    await waitFor(() => expect(screen.getAllByText(capability.label).length).toBeGreaterThan(0));
  });

  it("links back to the Threat Intelligence overview", async () => {
    effectiveAccessMock.mockResolvedValue({ effective_permissions: [capability.tenantReadPerm] });
    render(<ComingSoon capability={capability} />);
    await waitFor(() =>
      expect(screen.getByText(/Threat Intelligence overview/).closest("a")).toHaveAttribute(
        "href",
        "/threat-intelligence",
      ),
    );
  });
});
