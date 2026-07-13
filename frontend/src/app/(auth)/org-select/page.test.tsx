import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import * as auth from "@/lib/auth";
import { ApiError, setToken } from "@/lib/api";
import OrgSelectPage from "./page";

const replaceMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace: replaceMock, push: replaceMock }),
}));

vi.mock("@/lib/auth", async () => {
  const actual = await vi.importActual<typeof import("@/lib/auth")>("@/lib/auth");
  return {
    ...actual,
    getAccessibleOrganizations: vi.fn(),
    selectOrganization: vi.fn(),
    createOrganization: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
  sessionStorage.clear();
});

function org(overrides: Partial<auth.AccessibleOrganization> = {}): auth.AccessibleOrganization {
  return { id: "org-1", name: "Org One", slug: "org-one", status: "active", plan: "free", ...overrides };
}

describe("OrgSelectPage", () => {
  it("a zero-organization user reaches the organization bootstrap (setup) state, not a permanent loading state", async () => {
    setToken("valid-token");
    vi.mocked(auth.getAccessibleOrganizations).mockResolvedValue([]);
    render(<OrgSelectPage />);

    await waitFor(() => {
      expect(screen.getByText("Create Your Organization")).toBeInTheDocument();
    });
  });

  it("a single-organization user is auto-selected straight through to the dashboard", async () => {
    setToken("valid-token");
    vi.mocked(auth.getAccessibleOrganizations).mockResolvedValue([org()]);
    vi.mocked(auth.selectOrganization).mockResolvedValue({
      user_id: "u1", email: "e", display_name: "d",
      access_token: "scoped-token", refresh_token: "r", expires_in: 3600, token_type: "bearer",
    });
    render(<OrgSelectPage />);

    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/dashboard");
    });
  });

  it("a multi-organization user sees the explicit selection UI, not a permanent loading state", async () => {
    setToken("valid-token");
    vi.mocked(auth.getAccessibleOrganizations).mockResolvedValue([
      org({ id: "org-1", name: "Org One" }),
      org({ id: "org-2", name: "Org Two" }),
    ]);
    render(<OrgSelectPage />);

    await waitFor(() => {
      expect(screen.getByText("Select Organization")).toBeInTheDocument();
    });
    expect(screen.getByText("Org One")).toBeInTheDocument();
    expect(screen.getByText("Org Two")).toBeInTheDocument();
  });

  it("organization discovery failure (non-auth error) shows a controlled error state, not a permanent loading state", async () => {
    setToken("valid-token");
    vi.mocked(auth.getAccessibleOrganizations).mockRejectedValue(
      new ApiError(500, "INTERNAL_ERROR", "Something went wrong")
    );
    render(<OrgSelectPage />);

    await waitFor(() => {
      expect(screen.getByText("Something went wrong")).toBeInTheDocument();
    });
  });

  it("an expired/invalid token (401) during organization discovery clears the session and returns to login — no dead-end error screen, no redirect loop", async () => {
    setToken("stale-invalid-token");
    vi.mocked(auth.getAccessibleOrganizations).mockRejectedValue(
      new ApiError(401, "AUTHENTICATION_ERROR", "Token expired")
    );
    render(<OrgSelectPage />);

    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/login");
    });
    expect(sessionStorage.getItem("redforge_token")).toBeNull();
  });

  it("an unauthenticated visitor is sent to login immediately, without ever calling the organizations endpoint", async () => {
    render(<OrgSelectPage />);

    await waitFor(() => {
      expect(replaceMock).toHaveBeenCalledWith("/login");
    });
    expect(auth.getAccessibleOrganizations).not.toHaveBeenCalled();
  });
});
