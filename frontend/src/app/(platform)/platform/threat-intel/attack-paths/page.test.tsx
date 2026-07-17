import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent } from "@testing-library/react";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) =>
    <a href={href} {...rest}>{children}</a>,
}));

vi.mock("@/lib/attackPathsApi", () => ({
  listAttackPaths: vi.fn(),
  computeAttackPath: vi.fn(),
  pathConfidenceColor: () => "border-emerald-800 bg-emerald-950/50 text-emerald-300",
  pathStatusColor: () => "border-red-800 bg-red-950/60 text-red-300",
}));

vi.mock("@/lib/platform", () => ({
  listPlatformOrganizations: vi.fn(),
}));

import * as attackPathsApi from "@/lib/attackPathsApi";
import * as platform from "@/lib/platform";
import AttackPathsPage from "./page";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const org = {
  id: "org-1",
  name: "Acme Corp",
  slug: "acme",
  status: "active",
  plan: "enterprise",
  created_at: "2024-01-01T00:00:00Z",
  updated_at: "2024-01-01T00:00:00Z",
};

describe("AttackPathsPage", () => {
  it("renders the page heading and org selector", async () => {
    vi.mocked(platform.listPlatformOrganizations).mockResolvedValue([org]);
    render(<AttackPathsPage />);
    expect(screen.getByText("Attack Paths")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Acme Corp")).toBeInTheDocument());
  });

  it("does not call listAttackPaths before org is selected", async () => {
    vi.mocked(platform.listPlatformOrganizations).mockResolvedValue([org]);
    render(<AttackPathsPage />);
    await waitFor(() => screen.getByText("Acme Corp"));
    expect(attackPathsApi.listAttackPaths).not.toHaveBeenCalled();
  });

  it("loads attack paths after org is selected via fireEvent.change", async () => {
    vi.mocked(platform.listPlatformOrganizations).mockResolvedValue([org]);
    vi.mocked(attackPathsApi.listAttackPaths).mockResolvedValue([]);
    const { container } = render(<AttackPathsPage />);
    await waitFor(() => screen.getByText("Acme Corp"));

    const select = container.querySelector("select") as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "org-1" } });

    await waitFor(() =>
      expect(attackPathsApi.listAttackPaths).toHaveBeenCalledWith(
        expect.objectContaining({ organization_id: "org-1" }),
      ),
    );
  });

  it("shows empty state when no attack paths exist for selected org", async () => {
    vi.mocked(platform.listPlatformOrganizations).mockResolvedValue([org]);
    vi.mocked(attackPathsApi.listAttackPaths).mockResolvedValue([]);
    const { container } = render(<AttackPathsPage />);
    await waitFor(() => screen.getByText("Acme Corp"));

    fireEvent.change(container.querySelector("select") as HTMLSelectElement, {
      target: { value: "org-1" },
    });

    await waitFor(() =>
      expect(
        screen.getByText("No attack paths found. Compute one above."),
      ).toBeInTheDocument(),
    );
  });

  it("shows error banner when list API fails", async () => {
    vi.mocked(platform.listPlatformOrganizations).mockResolvedValue([org]);
    vi.mocked(attackPathsApi.listAttackPaths).mockRejectedValue(new Error("fail"));
    const { container } = render(<AttackPathsPage />);
    await waitFor(() => screen.getByText("Acme Corp"));

    fireEvent.change(container.querySelector("select") as HTMLSelectElement, {
      target: { value: "org-1" },
    });

    await waitFor(() =>
      expect(screen.getByText("Failed to load attack paths.")).toBeInTheDocument(),
    );
  });
});
