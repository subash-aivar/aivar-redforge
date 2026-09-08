import { describe, it, expect, vi, afterEach } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { ConnectionIndicator, RealtimeTimestamp, StaleBadge } from "@/components/platform/LiveIndicators";

afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("RealtimeTimestamp", () => {
  it("renders 'never' for a null timestamp — never a fabricated time", () => {
    render(<RealtimeTimestamp iso={null} prefix="Last event: " />);
    expect(screen.getByText("Last event: never")).toBeInTheDocument();
  });

  it("renders a real relative time computed from the given ISO timestamp", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:01:00Z"));
    render(<RealtimeTimestamp iso="2026-01-01T00:00:30Z" />);
    expect(screen.getByText("30s ago")).toBeInTheDocument();
  });
});

describe("ConnectionIndicator", () => {
  it("renders the real connection state passed in, with label overrides applied", () => {
    render(<ConnectionIndicator state="reconnecting" labels={{ reconnecting: "Reconnecting" }} />);
    expect(screen.getByText("Reconnecting")).toBeInTheDocument();
  });

  it("defaults to the raw state string when no label override is given", () => {
    render(<ConnectionIndicator state="disconnected" />);
    expect(screen.getByText("disconnected")).toBeInTheDocument();
  });
});

describe("StaleBadge", () => {
  it("renders nothing when data is fresh", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:05Z"));
    const { container } = render(<StaleBadge iso="2026-01-01T00:00:00Z" thresholdMs={60_000} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders a real Stale flag once data exceeds the threshold — never hides real staleness", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:05:00Z"));
    render(<StaleBadge iso="2026-01-01T00:00:00Z" thresholdMs={60_000} />);
    expect(screen.getByText("Stale")).toBeInTheDocument();
  });
});
