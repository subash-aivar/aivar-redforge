import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import ThreatIntelligenceLayout from "./layout";

let currentPath = "/threat-intelligence";
vi.mock("next/navigation", () => ({
  usePathname: () => currentPath,
}));

afterEach(() => {
  cleanup();
  currentPath = "/threat-intelligence";
});

describe("ThreatIntelligenceLayout", () => {
  it("renders one Overview tab plus a tab for every capability", () => {
    render(
      <ThreatIntelligenceLayout>
        <div>child content</div>
      </ThreatIntelligenceLayout>,
    );
    expect(screen.getByText("Overview")).toBeInTheDocument();
    expect(screen.getByText("IOC Intelligence")).toBeInTheDocument();
    expect(screen.getByText("Threat Actors")).toBeInTheDocument();
    expect(screen.getByText("Attack Patterns")).toBeInTheDocument();
    expect(screen.getByText("Malware")).toBeInTheDocument();
    expect(screen.getByText("Campaigns")).toBeInTheDocument();
    expect(screen.getByText("Adversary Tools")).toBeInTheDocument();
    expect(screen.getByText("Infrastructure")).toBeInTheDocument();
    expect(screen.getByText("Threat Reports")).toBeInTheDocument();
    expect(screen.getByText("Relationships")).toBeInTheDocument();
  });

  it("renders Knowledge Graph and Knowledge Quality as disabled, non-navigable planned surfaces", () => {
    render(
      <ThreatIntelligenceLayout>
        <div />
      </ThreatIntelligenceLayout>,
    );
    const kg = screen.getByText("Knowledge Graph");
    const kq = screen.getByText("Knowledge Quality");
    expect(kg.closest("a")).toBeNull();
    expect(kq.closest("a")).toBeNull();
    expect(kg.closest('[aria-disabled="true"]')).not.toBeNull();
    expect(screen.getAllByText("Planned").length).toBeGreaterThanOrEqual(2);
  });

  it("marks the tab matching the current pathname as active", () => {
    currentPath = "/threat-intelligence/malware";
    render(
      <ThreatIntelligenceLayout>
        <div />
      </ThreatIntelligenceLayout>,
    );
    expect(screen.getByText("Malware").closest("a")).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("Overview").closest("a")).not.toHaveAttribute("aria-current");
  });

  it("renders passed children", () => {
    render(
      <ThreatIntelligenceLayout>
        <div data-testid="child-marker">hello</div>
      </ThreatIntelligenceLayout>,
    );
    expect(screen.getByTestId("child-marker")).toBeInTheDocument();
  });

  it("IOC Intelligence tab links outside the /threat-intelligence prefix, to the existing live route", () => {
    render(
      <ThreatIntelligenceLayout>
        <div />
      </ThreatIntelligenceLayout>,
    );
    expect(screen.getByText("IOC Intelligence").closest("a")).toHaveAttribute(
      "href",
      "/ioc-intelligence",
    );
  });
});
