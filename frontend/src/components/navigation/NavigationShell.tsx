"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";
import { NAV_GROUPS, isItemActive } from "@/components/navigation/navConfig";
import {
  NavGroupSection,
  NavLink,
} from "@/components/navigation/NavGroupSection";
import { QuickSearch } from "@/components/navigation/QuickSearch";
import { useNavPreferences } from "@/components/navigation/useNavPreferences";
import { usePlatformEventBus } from "@/components/platform/EventBusProvider";
import { computeLiveNavBadges } from "@/components/navigation/liveNavBadges";
import { useAsync } from "@/components/cc";
import { getRuntimeStatus } from "@/lib/runtime";

interface NavigationShellProps {
  pathname: string;
  /** RBAC gate — passed in from `AppLayout`, computed exactly as
   * before (`!perm || perms === null || perms.has(perm)`). This
   * component never re-derives permission logic itself. */
  can: (perm?: string) => boolean;
  hasPlatformAccess: boolean;
  user: { display_name: string; email: string };
  onSwitchOrg: () => void;
  onSignOut: () => void;
  /** Below the `md` breakpoint the sidebar becomes an off-canvas
   * drawer instead of a persistent column — `AppLayout` owns the
   * open/close boolean (and its trigger button) and passes it down so
   * there is still exactly one navigation render, not a second mobile
   * tree. Both default closed/no-op so every existing desktop caller
   * (and every existing test) keeps working unchanged. */
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

/**
 * Enterprise navigation shell: grouped + collapsible sections, a
 * pinned Favorites row, a pinned Recently Visited row, and quick
 * search (Ctrl/Cmd+K) — replacing the previous always-expanded flat
 * scroll. Every item still passes through the exact same `can(perm)`
 * gate the caller supplies; this component adds presentation only.
 */
export function NavigationShell({
  pathname,
  can,
  hasPlatformAccess,
  user,
  onSwitchOrg,
  onSignOut,
  mobileOpen = false,
  onCloseMobile = () => {},
}: NavigationShellProps) {
  const router = useRouter();
  const {
    favorites,
    recents,
    collapsedGroups,
    toggleFavorite,
    toggleGroupCollapsed,
  } = useNavPreferences(pathname);

  const asideRef = useRef<HTMLElement>(null);
  // Resolved synchronously (lazy initializer, not an effect) so the
  // very first render already has the real value — deferring this to
  // an effect left a one-render window where a component that mounts
  // already `mobileOpen` on a narrow viewport would still read the
  // `true` (desktop) default, and the resize-safety effect below would
  // wrongly fire `onCloseMobile()` on mount. Falls back to `true`
  // (desktop) only when `matchMedia` genuinely isn't available.
  const [isDesktop, setIsDesktop] = useState(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return true;
    return window.matchMedia("(min-width: 768px)").matches;
  });

  useEffect(() => {
    // Some test/embedded runtimes don't implement matchMedia — degrade
    // to the safe default (isDesktop stays true) rather than crash.
    if (typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia("(min-width: 768px)");
    const onChange = (e: MediaQueryListEvent) => setIsDesktop(e.matches);
    mql.addEventListener("change", onChange);
    return () => mql.removeEventListener("change", onChange);
  }, []);

  // A resize that crosses back onto desktop while the drawer is open
  // must not leave it modeled as still-open. Tracks the *transition*
  // (previously not-desktop, now desktop) rather than just "currently
  // desktop && open" — the trigger that sets `mobileOpen` is itself
  // `md:hidden`, so in real usage `isDesktop` is never already `true`
  // at the moment `mobileOpen` becomes `true`; guarding on the
  // transition keeps that invariant explicit instead of relying on it.
  const wasDesktopRef = useRef(isDesktop);
  useEffect(() => {
    if (isDesktop && !wasDesktopRef.current && mobileOpen) onCloseMobile();
    wasDesktopRef.current = isDesktop;
  }, [isDesktop, mobileOpen, onCloseMobile]);

  // Background scroll must not leak behind the open mobile drawer.
  useEffect(() => {
    if (!mobileOpen) return;
    const previous = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previous;
    };
  }, [mobileOpen]);

  // Focus trap + Escape-to-close + initial focus into the drawer.
  // Focus-return-to-trigger is the trigger owner's job (`AppLayout`),
  // done inside the `onCloseMobile` callback it supplies — this effect
  // only manages focus while the drawer itself is open, matching the
  // exact Tab-cycling approach `InvestigationDrawer` already uses.
  useEffect(() => {
    if (!mobileOpen) return;
    const focusable = asideRef.current?.querySelectorAll<HTMLElement>(
      'button, a[href], input, [tabindex]:not([tabindex="-1"])',
    );
    focusable?.[0]?.focus();

    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        onCloseMobile();
        return;
      }
      if (e.key !== "Tab") return;
      const nodes = asideRef.current?.querySelectorAll<HTMLElement>(
        'button, a[href], input, [tabindex]:not([tabindex="-1"])',
      );
      if (!nodes || nodes.length === 0) return;
      const first = nodes[0];
      const last = nodes[nodes.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [mobileOpen, onCloseMobile]);

  // Selecting any route (a real nav link, not the programmatic
  // QuickSearch navigate below) closes the mobile drawer — one
  // capture-phase listener covers every `NavLink`/`NavGroupSection`
  // link (favorites, recents, groups) without touching those
  // components' own signatures.
  function handleAsideClick(e: React.MouseEvent<HTMLElement>) {
    if (!mobileOpen) return;
    if ((e.target as HTMLElement).closest("a[href]")) onCloseMobile();
  }

  const { events } = usePlatformEventBus();
  const badges = useMemo(() => computeLiveNavBadges(events), [events]);

  const runtimeStatus = useAsync(() => getRuntimeStatus(), []);
  const health:
    Record<string, "healthy" | "degraded" | "unhealthy"> | undefined =
    useMemo(() => {
      if (!runtimeStatus.data) return undefined;
      const status: "healthy" | "degraded" | "unhealthy" =
        runtimeStatus.data.overall_health === "healthy"
          ? "healthy"
          : runtimeStatus.data.overall_health === "degraded"
            ? "degraded"
            : "unhealthy";
      return { "/health": status };
    }, [runtimeStatus.data]);

  const visibleGroups = useMemo(
    () =>
      NAV_GROUPS.map((group) => ({
        ...group,
        items: group.items.filter((item) => can(item.perm)),
      })).filter((group) => group.items.length > 0),
    [can],
  );

  const itemByHref = useMemo(() => {
    const map = new Map<string, { label: string; icon: string }>();
    for (const group of visibleGroups) {
      for (const item of group.items) map.set(item.href, item);
    }
    return map;
  }, [visibleGroups]);

  const favoriteItems = favorites
    .map((href) => itemByHref.get(href))
    .filter(Boolean) as {
    label: string;
    icon: string;
  }[];
  const favoriteHrefs = favorites.filter((href) => itemByHref.has(href));

  const recentItems = recents
    .filter((href) => href !== pathname && itemByHref.has(href))
    .slice(0, 5);

  return (
    <>
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 md:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}
      <aside
        ref={asideRef}
        id="app-mobile-nav"
        onClickCapture={handleAsideClick}
        role={mobileOpen ? "dialog" : undefined}
        aria-modal={mobileOpen ? true : undefined}
        aria-label="Primary navigation"
        inert={!isDesktop && !mobileOpen ? true : undefined}
        className={`fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r border-gray-800 bg-gray-900 transition-transform duration-200 ease-out motion-reduce:transition-none md:static md:z-auto md:w-64 md:max-w-none md:translate-x-0 md:transition-none ${
          mobileOpen ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex h-14 items-center border-b border-gray-800 px-5">
          <span className="text-lg font-bold text-red-500">RedForge</span>
        </div>

        <div className="border-b border-gray-800 px-3 py-3">
          <QuickSearch
            groups={visibleGroups}
            onNavigate={(href) => {
              router.push(href);
              if (mobileOpen) onCloseMobile();
            }}
          />
        </div>

        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
          {favoriteHrefs.length > 0 && (
            <div>
              <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                Favorites
              </div>
              <div className="space-y-0.5">
                {favoriteHrefs.map((href, i) => (
                  <NavLink
                    key={href}
                    href={href}
                    icon={favoriteItems[i]?.icon ?? "★"}
                    label={favoriteItems[i]?.label ?? href}
                    active={isItemActive(pathname, href)}
                    favorited
                    onToggleFavorite={() => toggleFavorite(href)}
                    badgeCount={badges[href]}
                    health={health?.[href]}
                  />
                ))}
              </div>
            </div>
          )}

          {recentItems.length > 0 && (
            <div>
              <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                Recently Visited
              </div>
              <div className="space-y-0.5">
                {recentItems.map((href) => {
                  const item = itemByHref.get(href)!;
                  return (
                    <NavLink
                      key={href}
                      href={href}
                      icon={item.icon}
                      label={item.label}
                      active={false}
                      favorited={favorites.includes(href)}
                      onToggleFavorite={() => toggleFavorite(href)}
                      badgeCount={badges[href]}
                      health={health?.[href]}
                    />
                  );
                })}
              </div>
            </div>
          )}

          {visibleGroups.map((group) => (
            <NavGroupSection
              key={group.title}
              group={group}
              pathname={pathname}
              collapsed={collapsedGroups.includes(group.title)}
              onToggleCollapsed={() => toggleGroupCollapsed(group.title)}
              favorites={favorites}
              onToggleFavorite={toggleFavorite}
              badges={badges}
              health={health}
            />
          ))}
        </nav>

        {hasPlatformAccess && (
          <div className="border-t border-gray-800 px-3 py-3">
            <Link
              href="/platform/overview"
              className="flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-purple-400 hover:bg-purple-950/30"
            >
              <span className="text-base">⬢</span>
              Platform Control Plane
            </Link>
          </div>
        )}

        <div className="border-t border-gray-800 px-4 py-3">
          <div className="text-sm text-gray-300">{user.display_name}</div>
          <div className="text-xs text-gray-500">{user.email}</div>
          <button
            onClick={onSwitchOrg}
            className="mt-1 text-xs text-gray-500 hover:text-gray-300"
          >
            Switch org
          </button>
          <button
            onClick={onSignOut}
            className="mt-1 block text-xs text-gray-500 hover:text-red-400"
          >
            Sign out
          </button>
        </div>
      </aside>
    </>
  );
}
