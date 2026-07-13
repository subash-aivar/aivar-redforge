import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";

/**
 * Root-cause regression coverage for the API-origin browser bug: the
 * app must reach the backend via a same-origin relative path by
 * default (so it works identically on http://localhost:3000 and
 * http://<lan-ip>:3000 — see next.config.ts's rewrites()), and must
 * still honor an explicit NEXT_PUBLIC_API_URL override when set.
 *
 * API_BASE is a module-level constant computed from process.env at
 * import time, so each case resets modules and re-imports fresh.
 */
describe("api base resolution", () => {
  const originalEnv = process.env.NEXT_PUBLIC_API_URL;

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    process.env.NEXT_PUBLIC_API_URL = originalEnv;
    vi.unstubAllGlobals();
  });

  it("defaults to a same-origin relative path when NEXT_PUBLIC_API_URL is unset (localhost and LAN hosts both work with zero config)", async () => {
    delete process.env.NEXT_PUBLIC_API_URL;
    const { getApiBase } = await import("./api");
    expect(getApiBase()).toBe("");
  });

  it("does not hardcode any absolute localhost origin when unset", async () => {
    delete process.env.NEXT_PUBLIC_API_URL;
    const { api } = await import("./api");
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    );
    vi.stubGlobal("fetch", fetchMock);
    await api.get("/api/v1/health");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/v1/health",
      expect.objectContaining({ method: "GET" })
    );
  });

  it("respects an explicit NEXT_PUBLIC_API_URL override when set", async () => {
    process.env.NEXT_PUBLIC_API_URL = "https://api.explicit-override.example";
    const { getApiBase, api } = await import("./api");
    expect(getApiBase()).toBe("https://api.explicit-override.example");

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 })
    );
    vi.stubGlobal("fetch", fetchMock);
    await api.get("/api/v1/health");
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.explicit-override.example/api/v1/health",
      expect.objectContaining({ method: "GET" })
    );
  });
});
