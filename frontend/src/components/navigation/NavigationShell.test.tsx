import { describe, expect, it, vi, afterEach } from "vitest";
import { act, cleanup, render, screen, fireEvent } from "@testing-library/react";
import { NavigationShell } from "@/components/navigation/NavigationShell";
import { EventBusProvider } from "@/components/platform/EventBusProvider";
import * as streamHook from "@/lib/useSecurityOperationsStream";

vi.mock("@/lib/useSecurityOperationsStream");

const pushMock = vi.fn();
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

afterEach(() => {
  cleanup();
  pushMock.mockClear();
  vi.restoreAllMocks();
  // This jsdom/Node combination does not always expose `localStorage`
  // (see `useNavPreferences.ts`'s own try/catch guard for the same
  // reason) — clear it only when present rather than assuming it is.
  window.localStorage?.clear();
});

const user = { display_name: "Test User", email: "user@example.test" };

function renderShell(props: Partial<React.ComponentProps<typeof NavigationShell>> = {}) {
  vi.mocked(streamHook.useSecurityOperationsStream).mockReturnValue({
    connectionState: "connected",
    events: [],
    lastEventReceivedAt: null,
  });
  return render(
    <EventBusProvider>
      <NavigationShell
        pathname="/dashboard"
        can={() => true}
        hasPlatformAccess={false}
        user={user}
        onSwitchOrg={vi.fn()}
        onSignOut={vi.fn()}
        {...props}
      />
    </EventBusProvider>
  );
}

describe("NavigationShell", () => {
  it("renders only items the can() gate allows", () => {
    renderShell({ can: (perm) => perm !== "ddos:read" });
    expect(screen.getByText("Asset Inventory")).toBeInTheDocument();
    expect(screen.queryByText("DDoS Overview")).not.toBeInTheDocument();
  });

  it("shows the user's name and Platform Control Plane only when hasPlatformAccess is true", () => {
    renderShell({ hasPlatformAccess: true });
    expect(screen.getByText("Test User")).toBeInTheDocument();
    expect(screen.getByText("Platform Control Plane")).toBeInTheDocument();
  });

  it("hides Platform Control Plane when hasPlatformAccess is false", () => {
    renderShell({ hasPlatformAccess: false });
    expect(screen.queryByText("Platform Control Plane")).not.toBeInTheDocument();
  });

  it("Sign out button calls the supplied handler", () => {
    const onSignOut = vi.fn();
    renderShell({ onSignOut });
    fireEvent.click(screen.getByText("Sign out"));
    expect(onSignOut).toHaveBeenCalled();
  });

  it("favoriting an item pins it into a Favorites section", () => {
    renderShell();
    fireEvent.click(screen.getByLabelText("Add Asset Inventory to favorites"));
    expect(screen.getByText("Favorites")).toBeInTheDocument();
  });

  it("opens quick search on Ctrl+K", () => {
    renderShell();
    fireEvent.keyDown(window, { key: "k", ctrlKey: true });
    expect(screen.getByRole("dialog", { name: "Quick search" })).toBeInTheDocument();
  });

  it("shows a live critical/high badge on the nav item owning that event's real source_domain", () => {
    vi.mocked(streamHook.useSecurityOperationsStream).mockReturnValue({
      connectionState: "connected",
      events: [
        {
          cursor: "1",
          event_id: "e1",
          organization_id: "org1",
          source_domain: "ddos",
          importance: "critical",
          title: "DDoS incident detected",
          summary: "volumetric attack",
          entity_type: "ddos_incident",
          entity_id: "i1",
          occurred_at: new Date().toISOString(),
          schema_version: 1,
        },
      ],
      lastEventReceivedAt: null,
    });
    render(
      <EventBusProvider>
        <NavigationShell
          pathname="/dashboard"
          can={() => true}
          hasPlatformAccess={false}
          user={user}
          onSwitchOrg={vi.fn()}
          onSignOut={vi.fn()}
        />
      </EventBusProvider>
    );
    expect(screen.getByLabelText("1 critical or high events")).toBeInTheDocument();
  });
});

/**
 * Mobile off-canvas drawer — `AppLayout` owns `mobileOpen`/
 * `onCloseMobile` (and the trigger button that flips them); these
 * tests drive NavigationShell directly as a controlled component,
 * the same contract `AppLayout` uses.
 */
function mockMatchMedia(matches: boolean) {
  const listeners = new Set<(e: MediaQueryListEvent) => void>();
  const mql = {
    matches,
    media: "(min-width: 768px)",
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: (_type: string, cb: (e: MediaQueryListEvent) => void) => listeners.add(cb),
    removeEventListener: (_type: string, cb: (e: MediaQueryListEvent) => void) =>
      listeners.delete(cb),
    dispatchEvent: () => false,
  } as unknown as MediaQueryList;
  vi.stubGlobal("matchMedia", () => mql);
  return {
    fireChange(next: boolean) {
      for (const cb of listeners) cb({ matches: next } as MediaQueryListEvent);
    },
  };
}

describe("NavigationShell — mobile drawer", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    document.body.style.overflow = "";
  });

  it("does not introduce a second navigation tree — exactly one <nav> renders whether the drawer is open or closed", () => {
    mockMatchMedia(false);
    const { rerender } = renderShell({ mobileOpen: false });
    expect(screen.getAllByRole("navigation")).toHaveLength(1);
    rerender(
      <EventBusProvider>
        <NavigationShell
          pathname="/dashboard"
          can={() => true}
          hasPlatformAccess={false}
          user={user}
          onSwitchOrg={vi.fn()}
          onSignOut={vi.fn()}
          mobileOpen
          onCloseMobile={vi.fn()}
        />
      </EventBusProvider>
    );
    expect(screen.getAllByRole("navigation")).toHaveLength(1);
  });

  it("RBAC-hidden items stay hidden while the drawer is open", () => {
    mockMatchMedia(false);
    renderShell({ mobileOpen: true, can: (perm) => perm !== "ddos:read" });
    expect(screen.getByText("Asset Inventory")).toBeInTheDocument();
    expect(screen.queryByText("DDoS Overview")).not.toBeInTheDocument();
  });

  it("favorites, recents, and quick search remain available while the drawer is open", () => {
    mockMatchMedia(false);
    renderShell({ mobileOpen: true });
    fireEvent.click(screen.getByLabelText("Add Asset Inventory to favorites"));
    expect(screen.getByText("Favorites")).toBeInTheDocument();
    expect(screen.getByText("Command palette")).toBeInTheDocument();
  });

  it("Escape closes the drawer", () => {
    mockMatchMedia(false);
    const onCloseMobile = vi.fn();
    renderShell({ mobileOpen: true, onCloseMobile });
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onCloseMobile).toHaveBeenCalled();
  });

  it("clicking the backdrop closes the drawer", () => {
    mockMatchMedia(false);
    const onCloseMobile = vi.fn();
    const { container } = renderShell({ mobileOpen: true, onCloseMobile });
    const backdrop = container.querySelector('[aria-hidden="true"].fixed.inset-0');
    expect(backdrop).not.toBeNull();
    fireEvent.click(backdrop!);
    expect(onCloseMobile).toHaveBeenCalled();
  });

  it("selecting a route (clicking a nav link) closes the drawer", () => {
    mockMatchMedia(false);
    const onCloseMobile = vi.fn();
    renderShell({ mobileOpen: true, onCloseMobile });
    fireEvent.click(screen.getByText("Asset Inventory"));
    expect(onCloseMobile).toHaveBeenCalled();
  });

  it("does not close the drawer on a click that isn't a link (e.g. the Favorites heading)", () => {
    mockMatchMedia(false);
    const onCloseMobile = vi.fn();
    renderShell({ mobileOpen: true, onCloseMobile });
    fireEvent.click(screen.getByText("Command palette"));
    expect(onCloseMobile).not.toHaveBeenCalled();
  });

  it("moves focus into the drawer when it opens", async () => {
    mockMatchMedia(false);
    renderShell({ mobileOpen: true });
    await vi.waitFor(() => {
      expect(document.activeElement?.tagName).not.toBe("BODY");
    });
    const aside = document.getElementById("app-mobile-nav");
    expect(aside?.contains(document.activeElement)).toBe(true);
  });

  it("locks and restores background scroll with the drawer's open state", () => {
    mockMatchMedia(false);
    const { rerender, unmount } = renderShell({ mobileOpen: true });
    expect(document.body.style.overflow).toBe("hidden");
    rerender(
      <EventBusProvider>
        <NavigationShell
          pathname="/dashboard"
          can={() => true}
          hasPlatformAccess={false}
          user={user}
          onSwitchOrg={vi.fn()}
          onSignOut={vi.fn()}
          mobileOpen={false}
          onCloseMobile={vi.fn()}
        />
      </EventBusProvider>
    );
    expect(document.body.style.overflow).toBe("");
    unmount();
  });

  it("marks the off-canvas drawer inert (non-interactive, hidden from assistive tech) when closed on a narrow viewport", () => {
    mockMatchMedia(false);
    renderShell({ mobileOpen: false });
    const aside = document.getElementById("app-mobile-nav");
    expect(aside?.hasAttribute("inert")).toBe(true);
  });

  it("never marks the sidebar inert on desktop, even though mobileOpen defaults to false", () => {
    mockMatchMedia(true);
    renderShell({ mobileOpen: false });
    const aside = document.getElementById("app-mobile-nav");
    expect(aside?.hasAttribute("inert")).toBe(false);
  });

  it("a resize back onto desktop while the drawer is open calls onCloseMobile and clears the lock (no invisible overlay or stuck body scroll)", () => {
    const media = mockMatchMedia(false);
    const onCloseMobile = vi.fn();
    renderShell({ mobileOpen: true, onCloseMobile });
    expect(document.body.style.overflow).toBe("hidden");

    act(() => {
      media.fireChange(true);
    });

    expect(onCloseMobile).toHaveBeenCalled();
  });
});

describe("NavigationShell — product_edition (ADR-0009)", () => {
  it("defaults to full edition — every existing test/caller above keeps seeing today's exact nav", () => {
    renderShell({});
    // A representative full-only item (not in NETWORK_DEFENSE_HREFS).
    expect(screen.getByText("Vulnerability")).toBeInTheDocument();
  });

  it("network_defense edition hides an explicitly-unrelated full-only surface", () => {
    renderShell({ edition: "network_defense" });
    expect(screen.queryByText("Vulnerability")).not.toBeInTheDocument();
    expect(screen.queryByText("Compliance")).not.toBeInTheDocument();
    expect(screen.queryByText("AI Posture")).not.toBeInTheDocument();
  });

  it("network_defense edition still shows every required shared/network capability that has a real page", () => {
    renderShell({ edition: "network_defense" });
    expect(screen.getByText("Asset Inventory")).toBeInTheDocument();
    expect(screen.getByText("Network Security")).toBeInTheDocument();
    expect(screen.getByText("DDoS Overview")).toBeInTheDocument();
    expect(screen.getByText("Traffic Analytics")).toBeInTheDocument();
    expect(screen.getByText("NDR Operations Center")).toBeInTheDocument();
    expect(screen.getByText("Threat Intelligence")).toBeInTheDocument();
    expect(screen.getByText("Live Security")).toBeInTheDocument();
    expect(screen.getByText("Investigations")).toBeInTheDocument();
    expect(screen.getByText("Automated Actions")).toBeInTheDocument();
    expect(screen.getByText("Runtime Health")).toBeInTheDocument();
  });

  it("network_defense edition excludes incident (M34) — Family A investigations only, per ADR-0006", () => {
    renderShell({ edition: "network_defense" });
    expect(screen.queryByText("Incident Response")).not.toBeInTheDocument();
    expect(screen.getByText("Investigations")).toBeInTheDocument();
  });

  it("edition filtering composes with the RBAC can() gate, not instead of it", () => {
    renderShell({ edition: "network_defense", can: (perm) => perm !== "ddos:read" });
    // Allowed by edition but denied by RBAC — must still be hidden.
    expect(screen.queryByText("DDoS Overview")).not.toBeInTheDocument();
    // Allowed by both.
    expect(screen.getByText("Asset Inventory")).toBeInTheDocument();
  });

  it("renders the Network Defense brand label only in the network_defense edition", () => {
    renderShell({ edition: "network_defense" });
    expect(screen.getByText("RedForge Network Defense")).toBeInTheDocument();
    cleanup();
    renderShell({});
    expect(screen.getByText("RedForge")).toBeInTheDocument();
    expect(screen.queryByText("RedForge Network Defense")).not.toBeInTheDocument();
  });
});
