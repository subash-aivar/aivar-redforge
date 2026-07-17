import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import ComplianceLayout from "./layout";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

vi.mock("next/navigation", () => ({
  usePathname: () => "/compliance",
}));

vi.mock("next/link", () => ({
  default: ({
    children,
    href,
    ...rest
  }: {
    children: React.ReactNode;
    href: string;
  }) => (
    <a href={href} {...rest}>
      {children}
    </a>
  ),
}));

describe("ComplianceLayout", () => {
  it("exposes section navigation with accessible name", () => {
    render(
      <ComplianceLayout>
        <div>child</div>
      </ComplianceLayout>
    );
    const nav = screen.getByRole("navigation", {
      name: /Compliance console sections/i,
    });
    expect(nav).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Overview$/i })).toHaveAttribute(
      "href",
      "/compliance"
    );
    expect(
      screen.getByRole("link", { name: /^Recommendations$/i })
    ).toHaveAttribute("href", "/compliance/recommendations");
  });
});
