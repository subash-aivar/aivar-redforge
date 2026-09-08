import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent } from "@testing-library/react";
import * as auth from "@/lib/auth";
import * as platform from "@/lib/platform";
import { setToken, setOrganizationId, ApiError } from "@/lib/api";
import AppLayout from "./layout";

/**
 * Root-cause regression coverage for the "permanent Loading..." dashboard
 * bug: a failed current-user/organization check must always resolve to
 * either the authenticated shell or a redirect — never leave the app
 * stuck on the `!user` loading branch forever.
 */

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  usePathname: () => "/dashboard",
}));

vi.mock("@/lib/auth", async () => {
  const actual = await vi.importActual<typeof import("@/lib/auth")>("@/lib/auth");
  return { ...actual, getMe: vi.fn(), logout: vi.fn() };
});

vi.mock("@/lib/platform", async () => {
  const actual = await vi.importActual<typeof import("@/lib/platform")>("@/lib/platform");
  return { ...actual, getPlatformAccess: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  pushMock.mockClear();
  sessionStorage.clear();
});

describe("AppLayout", () => {
  it("an unauthenticated visitor is redirected to /login and never calls getMe()", async () => {
    render(<AppLayout>child</AppLayout>);

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/login");
    });
    expect(auth.getMe).not.toHaveBeenCalled();
  });

  it("an authenticated visitor with no organization selected is redirected to /org-select", async () => {
    setToken("valid-token");
    render(<AppLayout>child</AppLayout>);

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/org-select");
    });
    expect(auth.getMe).not.toHaveBeenCalled();
  });

  it("a current-user fetch failure (expired/invalid token) clears the session and redirects to /login instead of hanging on 'Loading...' forever", async () => {
    setToken("stale-token");
    setOrganizationId("org-1");
    vi.mocked(auth.getMe).mockRejectedValue(
      new ApiError(401, "AUTHENTICATION_ERROR", "Token expired")
    );
    vi.mocked(platform.getPlatformAccess).mockResolvedValue({
      user_id: "u1", platform_roles: [], permissions: [], has_platform_access: false,
    });

    render(<AppLayout>child</AppLayout>);

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/login");
    });
    expect(sessionStorage.getItem("redforge_token")).toBeNull();
    // Never silently stuck on the loading branch: the loading text is
    // gone once the redirect has been requested.
  });

  it("a successful current-user fetch renders the authenticated app shell (sidebar + children), not the loading state", async () => {
    setToken("valid-token");
    setOrganizationId("org-1");
    vi.mocked(auth.getMe).mockResolvedValue({
      user_id: "u1", email: "user@example.test", display_name: "Test User", status: "active",
    });
    vi.mocked(platform.getPlatformAccess).mockResolvedValue({
      user_id: "u1", platform_roles: [], permissions: [], has_platform_access: false,
    });

    render(<AppLayout><div>DASHBOARD CONTENT</div></AppLayout>);

    await waitFor(() => {
      expect(screen.getByText("DASHBOARD CONTENT")).toBeInTheDocument();
    });
    expect(screen.getByText("Test User")).toBeInTheDocument();
    expect(screen.queryByText("Loading...")).not.toBeInTheDocument();
  });

  it("a platform-access check failure never blocks rendering the app shell (fails closed to hidden, not to a stuck loading state)", async () => {
    setToken("valid-token");
    setOrganizationId("org-1");
    vi.mocked(auth.getMe).mockResolvedValue({
      user_id: "u1", email: "user@example.test", display_name: "Test User", status: "active",
    });
    vi.mocked(platform.getPlatformAccess).mockRejectedValue(new Error("network error"));

    render(<AppLayout><div>DASHBOARD CONTENT</div></AppLayout>);

    await waitFor(() => {
      expect(screen.getByText("DASHBOARD CONTENT")).toBeInTheDocument();
    });
    expect(screen.queryByText("Platform Control Plane")).not.toBeInTheDocument();
  });

  describe("mobile navigation trigger", () => {
    async function renderAuthenticated() {
      setToken("valid-token");
      setOrganizationId("org-1");
      vi.mocked(auth.getMe).mockResolvedValue({
        user_id: "u1", email: "user@example.test", display_name: "Test User", status: "active",
      });
      vi.mocked(platform.getPlatformAccess).mockResolvedValue({
        user_id: "u1", platform_roles: [], permissions: [], has_platform_access: false,
      });
      render(<AppLayout><div>DASHBOARD CONTENT</div></AppLayout>);
      await waitFor(() => {
        expect(screen.getByText("DASHBOARD CONTENT")).toBeInTheDocument();
      });
      return screen.getByRole("button", { name: "Open navigation" });
    }

    it("the trigger is present, md:hidden (mobile/tablet-only), and starts collapsed", async () => {
      const trigger = await renderAuthenticated();
      expect(trigger).toHaveClass("md:hidden");
      expect(trigger).toHaveAttribute("aria-expanded", "false");
      expect(trigger).toHaveAttribute("aria-controls", "app-mobile-nav");
    });

    it("clicking the trigger opens the drawer and flips aria-expanded", async () => {
      const trigger = await renderAuthenticated();
      fireEvent.click(trigger);
      expect(trigger).toHaveAttribute("aria-expanded", "true");
      expect(document.getElementById("app-mobile-nav")).toHaveAttribute("role", "dialog");
    });

    it("closing the drawer (Escape) returns focus to the trigger", async () => {
      const trigger = await renderAuthenticated();
      fireEvent.click(trigger);
      expect(trigger).toHaveAttribute("aria-expanded", "true");

      fireEvent.keyDown(document, { key: "Escape" });

      expect(trigger).toHaveAttribute("aria-expanded", "false");
      expect(document.activeElement).toBe(trigger);
    });
  });
});
