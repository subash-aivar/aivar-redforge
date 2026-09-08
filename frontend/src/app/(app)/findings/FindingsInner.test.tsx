import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import { api } from "@/lib/api";
import FindingsInner from "./FindingsInner";
import type { Finding } from "@/lib/types";

vi.mock("@/lib/api");

const pushMock = vi.fn();
let searchParams = new URLSearchParams();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
  useSearchParams: () => searchParams,
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  searchParams = new URLSearchParams();
});

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    organization_id: "org1",
    run_id: "run1",
    target_id: "target1",
    evidence_ids: [],
    title: "SQL injection in login form",
    description: "desc",
    severity: "high",
    risk_score: 7.2,
    status: "open",
    recommendation: "",
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

describe("FindingsInner cross-module pivot", () => {
  it("auto-expands the finding matching ?highlight=<id>, a real deep link from the Risk page", async () => {
    searchParams = new URLSearchParams("highlight=f2");
    vi.mocked(api.get).mockImplementation((url: string) => {
      if (url === "/api/v1/findings") {
        return Promise.resolve([
          makeFinding({ id: "f1", title: "First finding" }),
          makeFinding({ id: "f2", title: "Second finding" }),
        ]);
      }
      if (url.startsWith("/api/v1/evidence")) {
        return Promise.resolve({ items: [], total: 0, limit: 20, offset: 0 });
      }
      return Promise.reject(new Error("unexpected url " + url));
    });

    render(<FindingsInner />);

    await waitFor(() => {
      expect(screen.getByText("Evidence (0 items · run run1…)")).toBeInTheDocument();
    });
  });

  it("renders normally with no highlight param, no findings auto-expanded", async () => {
    searchParams = new URLSearchParams();
    vi.mocked(api.get).mockResolvedValue([makeFinding()]);

    render(<FindingsInner />);

    await waitFor(() => {
      expect(screen.getByText("SQL injection in login form")).toBeInTheDocument();
    });
    expect(screen.queryByText(/Evidence \(/)).not.toBeInTheDocument();
  });
});
