import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { NotificationCenter } from "@/components/navigation/NotificationCenter";
import { EventBusProvider } from "@/components/platform/EventBusProvider";
import * as streamHook from "@/lib/useSecurityOperationsStream";

vi.mock("@/lib/useSecurityOperationsStream");

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  window.localStorage?.clear();
});

function renderWithBus(ui: React.ReactElement) {
  return render(<EventBusProvider>{ui}</EventBusProvider>);
}

function mockStream(events: streamHook.SecurityOperationsStreamResult["events"]) {
  // NotificationCenter reads the shared stream via EventBusProvider, which
  // itself calls useSecurityOperationsStream exactly once — mocking the
  // underlying hook still covers it end-to-end without duplicating a
  // separate context mock.
  vi.mocked(streamHook.useSecurityOperationsStream).mockReturnValue({
    connectionState: "connected",
    events,
    lastEventReceivedAt: null,
  });
}

const criticalEvent = {
  cursor: "1",
  event_id: "e1",
  organization_id: "org1",
  source_domain: "runtime" as const,
  importance: "critical" as const,
  title: "Runtime component unhealthy",
  summary: "detection service degraded",
  entity_type: "component",
  entity_id: "c1",
  occurred_at: new Date().toISOString(),
  schema_version: 1,
};

const investigationEvent = {
  cursor: "2",
  event_id: "e2",
  organization_id: "org1",
  source_domain: "investigation" as const,
  importance: "high" as const,
  title: "Investigation case opened",
  summary: "case for correlated findings",
  entity_type: "investigation_case",
  entity_id: "case-123",
  occurred_at: new Date().toISOString(),
  schema_version: 1,
};

describe("NotificationCenter", () => {
  it("shows no unread badge when the real stream has delivered nothing", () => {
    mockStream([]);
    renderWithBus(<NotificationCenter />);
    expect(screen.queryByText(/unread/)).not.toBeInTheDocument();
  });

  it("groups real events by severity when opened", () => {
    mockStream([criticalEvent]);
    renderWithBus(<NotificationCenter />);

    fireEvent.click(screen.getByLabelText(/Notifications/));

    expect(screen.getByText("Critical (1)")).toBeInTheDocument();
    expect(screen.getByText("Runtime component unhealthy")).toBeInTheDocument();
  });

  it("shows an honest empty state, never a fabricated notification, when the stream is empty", () => {
    mockStream([]);
    renderWithBus(<NotificationCenter />);
    fireEvent.click(screen.getByLabelText(/Notifications/));
    expect(
      screen.getByText("No platform events yet. This panel updates in real time as they occur.")
    ).toBeInTheDocument();
  });

  it("filters by search query against title and summary", () => {
    mockStream([criticalEvent, investigationEvent]);
    renderWithBus(<NotificationCenter />);
    fireEvent.click(screen.getByLabelText(/Notifications/));

    fireEvent.change(screen.getByPlaceholderText("Search notifications…"), {
      target: { value: "investigation" },
    });

    expect(screen.getByText("Investigation case opened")).toBeInTheDocument();
    expect(screen.queryByText("Runtime component unhealthy")).not.toBeInTheDocument();
  });

  it("filters by severity chip", () => {
    mockStream([criticalEvent, investigationEvent]);
    renderWithBus(<NotificationCenter />);
    fireEvent.click(screen.getByLabelText(/Notifications/));

    fireEvent.click(screen.getByText("High"));

    expect(screen.getByText("Investigation case opened")).toBeInTheDocument();
    expect(screen.queryByText("Runtime component unhealthy")).not.toBeInTheDocument();
  });

  it("links to the real detail page for an entity_type this frontend actually has a route for", () => {
    mockStream([investigationEvent]);
    renderWithBus(<NotificationCenter />);
    fireEvent.click(screen.getByLabelText(/Notifications/));

    const link = screen.getByText("Open →");
    expect(link.closest("a")).toHaveAttribute("href", "/investigations/case-123");
  });

  it("does not render a link for an entity_type with no known real route", () => {
    mockStream([criticalEvent]);
    renderWithBus(<NotificationCenter />);
    fireEvent.click(screen.getByLabelText(/Notifications/));

    expect(screen.queryByText("Open →")).not.toBeInTheDocument();
  });

  it("pinning a notification moves it into the Pinned group", () => {
    mockStream([criticalEvent]);
    renderWithBus(<NotificationCenter />);
    fireEvent.click(screen.getByLabelText(/Notifications/));
    fireEvent.click(screen.getByLabelText("Pin notification"));

    expect(screen.getByText("Pinned (1)")).toBeInTheDocument();
    expect(screen.getByLabelText("Unpin notification")).toBeInTheDocument();
  });

  it("the trigger exposes aria-expanded/aria-haspopup/aria-controls, and the panel is a labelled, non-modal dialog", () => {
    mockStream([]);
    renderWithBus(<NotificationCenter />);
    const trigger = screen.getByLabelText(/Notifications/);
    expect(trigger).toHaveAttribute("aria-haspopup", "dialog");
    expect(trigger).toHaveAttribute("aria-expanded", "false");

    fireEvent.click(trigger);

    expect(trigger).toHaveAttribute("aria-expanded", "true");
    expect(trigger).toHaveAttribute("aria-controls", "notification-center-panel");
    const panel = screen.getByRole("dialog", { name: "Notifications" });
    expect(panel).toHaveAttribute("id", "notification-center-panel");
    expect(panel).toHaveAttribute("aria-modal", "false");
  });

  it("Escape closes the panel and returns focus to the trigger", () => {
    mockStream([criticalEvent]);
    renderWithBus(<NotificationCenter />);
    const trigger = screen.getByLabelText(/Notifications/);
    fireEvent.click(trigger);
    expect(screen.getByRole("dialog", { name: "Notifications" })).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Notifications" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("a new live event arriving while the panel is closed does not open it or move focus", () => {
    mockStream([]);
    const { rerender } = renderWithBus(<NotificationCenter />);
    const trigger = screen.getByLabelText(/Notifications/);
    const outsideButton = document.createElement("button");
    outsideButton.textContent = "elsewhere";
    document.body.appendChild(outsideButton);
    outsideButton.focus();

    mockStream([criticalEvent]);
    rerender(
      <EventBusProvider>
        <NotificationCenter />
      </EventBusProvider>
    );

    expect(screen.queryByRole("dialog", { name: "Notifications" })).not.toBeInTheDocument();
    expect(document.activeElement).toBe(outsideButton);
    expect(trigger).not.toHaveFocus();
    outsideButton.remove();
  });
});
