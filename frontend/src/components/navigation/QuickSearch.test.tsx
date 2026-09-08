import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { QuickSearch } from "@/components/navigation/QuickSearch";
import type { NavGroup } from "@/components/navigation/navConfig";

afterEach(() => {
  cleanup();
  window.localStorage?.clear();
});

const groups: NavGroup[] = [
  {
    title: "Command Center",
    items: [
      { label: "Findings", href: "/findings", icon: "⚠" },
      { label: "Firewall / IDS Wall", href: "/command-center/firewall", icon: "⛨" },
    ],
  },
];

describe("QuickSearch keyboard navigation", () => {
  it("moves the highlighted option with ArrowDown/ArrowUp and opens it on Enter", () => {
    const onNavigate = vi.fn();
    render(<QuickSearch groups={groups} onNavigate={onNavigate} />);
    fireEvent.click(screen.getByText("Command palette"));

    const input = screen.getByPlaceholderText("Search modules…");
    fireEvent.change(input, { target: { value: "fi" } });

    // Both "Findings" and "Firewall / IDS Wall" match "fi" — first is highlighted by default.
    expect(screen.getByRole("option", { name: /Findings/ })).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(screen.getByRole("option", { name: /Firewall/ })).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(input, { key: "ArrowUp" });
    expect(screen.getByRole("option", { name: /Findings/ })).toHaveAttribute("aria-selected", "true");

    fireEvent.keyDown(input, { key: "Enter" });
    expect(onNavigate).toHaveBeenCalledWith("/findings");
  });
});
