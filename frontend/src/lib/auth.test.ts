import { describe, it, expect, vi, afterEach } from "vitest";
import * as api from "./api";
import { login } from "./auth";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, api: { ...actual.api, post: vi.fn() } };
});

afterEach(() => {
  vi.restoreAllMocks();
  sessionStorage.clear();
});

describe("login()", () => {
  it("persists the access_token returned by the backend under the correct session key", async () => {
    vi.mocked(api.api.post).mockResolvedValue({
      user_id: "user-1",
      email: "user@example.test",
      display_name: "Test User",
      access_token: "the-real-access-token",
      refresh_token: "refresh-1",
      expires_in: 3600,
      token_type: "bearer",
    });

    await login("user@example.test", "correct-password");

    expect(sessionStorage.getItem("redforge_token")).toBe("the-real-access-token");
  });

  it("calls the login endpoint with exactly the email/password fields the backend expects", async () => {
    vi.mocked(api.api.post).mockResolvedValue({
      user_id: "user-1",
      email: "user@example.test",
      display_name: "Test User",
      access_token: "tok",
      refresh_token: "r",
      expires_in: 3600,
      token_type: "bearer",
    });

    await login("user@example.test", "correct-password");

    expect(api.api.post).toHaveBeenCalledWith("/api/v1/auth/login", {
      email: "user@example.test",
      password: "correct-password",
    });
  });
});
