import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as auth from "@/lib/auth";
import { ApiError } from "@/lib/api";
import LoginPage from "./page";

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/lib/auth", async () => {
  const actual = await vi.importActual<typeof import("@/lib/auth")>("@/lib/auth");
  return { ...actual, login: vi.fn(), register: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  pushMock.mockClear();
});

function fillAndSubmit(email: string, password: string) {
  fireEvent.change(screen.getByPlaceholderText("you@company.com"), {
    target: { value: email },
  });
  fireEvent.change(screen.getByPlaceholderText("••••••••"), {
    target: { value: password },
  });
  fireEvent.click(screen.getByRole("button", { name: "Sign In" }));
}

describe("LoginPage", () => {
  it("a failed login shows the error and exits the submitting state (button re-enables, no permanent 'Loading...')", async () => {
    vi.mocked(auth.login).mockRejectedValue(
      new ApiError(401, "AUTHENTICATION_ERROR", "Invalid email or password")
    );
    render(<LoginPage />);

    fillAndSubmit("user@example.test", "wrong-password");

    await waitFor(() => {
      expect(screen.getByText("Invalid email or password")).toBeInTheDocument();
    });
    const button = screen.getByRole("button", { name: "Sign In" });
    expect(button).not.toBeDisabled();
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("a non-ApiError failure (e.g. a network/CSP-blocked fetch) still exits the submitting state with a generic message, never a permanent loading state", async () => {
    vi.mocked(auth.login).mockRejectedValue(new TypeError("Failed to fetch"));
    render(<LoginPage />);

    fillAndSubmit("user@example.test", "any-password");

    await waitFor(() => {
      expect(screen.getByText("An unexpected error occurred")).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: "Sign In" })).not.toBeDisabled();
  });

  it("a successful login navigates to org-select (which owns auto-select / setup routing)", async () => {
    vi.mocked(auth.login).mockResolvedValue({
      user_id: "user-1",
      email: "user@example.test",
      display_name: "Test User",
      access_token: "token-abc",
      refresh_token: "refresh-abc",
      expires_in: 3600,
      token_type: "bearer",
    });
    render(<LoginPage />);

    fillAndSubmit("user@example.test", "correct-password");

    await waitFor(() => {
      expect(pushMock).toHaveBeenCalledWith("/org-select");
    });
  });
});
