"use client";

import Link from "next/link";
import { ChevronRight, Star } from "lucide-react";
import { useState } from "react";
import { isItemActive, type NavGroup } from "@/components/navigation/navConfig";

interface NavGroupSectionProps {
  group: NavGroup;
  pathname: string;
  collapsed: boolean;
  onToggleCollapsed: () => void;
  favorites: string[];
  onToggleFavorite: (href: string) => void;
  /** href -> live critical/high event count, from `liveNavBadges.ts`. */
  badges?: Record<string, number>;
  /** href -> real health status, currently only set for `/health`. */
  health?: Record<string, "healthy" | "degraded" | "unhealthy">;
}

/**
 * One collapsible nav group. When collapsed, the group header still
 * shows a chevron and — on hover — a flyout panel listing its items,
 * so a collapsed group's pages stay one hover away instead of
 * requiring an expand click first.
 */
export function NavGroupSection({
  group,
  pathname,
  collapsed,
  onToggleCollapsed,
  favorites,
  onToggleFavorite,
  badges,
  health,
}: NavGroupSectionProps) {
  const [flyoutOpen, setFlyoutOpen] = useState(false);

  return (
    <div
      className="relative"
      onMouseEnter={() => collapsed && setFlyoutOpen(true)}
      onMouseLeave={() => setFlyoutOpen(false)}
    >
      <button
        type="button"
        onClick={onToggleCollapsed}
        className="flex w-full items-center gap-1 px-3 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-600 hover:text-gray-400"
        aria-expanded={!collapsed}
      >
        <ChevronRight
          className={`h-3 w-3 shrink-0 transition-transform ${collapsed ? "" : "rotate-90"}`}
          aria-hidden="true"
        />
        {group.title}
      </button>

      {!collapsed && (
        <div className="space-y-0.5">
          {group.items.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              icon={item.icon}
              label={item.label}
              active={isItemActive(pathname, item.href)}
              favorited={favorites.includes(item.href)}
              onToggleFavorite={() => onToggleFavorite(item.href)}
              badgeCount={badges?.[item.href]}
              health={health?.[item.href]}
            />
          ))}
        </div>
      )}

      {collapsed && flyoutOpen && (
        <div className="absolute left-full top-0 z-40 ml-1 w-56 rounded-lg border border-gray-800 bg-gray-900 p-2 shadow-2xl">
          <div className="px-2 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
            {group.title}
          </div>
          {group.items.map((item) => (
            <NavLink
              key={item.href}
              href={item.href}
              icon={item.icon}
              label={item.label}
              active={isItemActive(pathname, item.href)}
              favorited={favorites.includes(item.href)}
              onToggleFavorite={() => onToggleFavorite(item.href)}
              badgeCount={badges?.[item.href]}
              health={health?.[item.href]}
            />
          ))}
        </div>
      )}
    </div>
  );
}

const HEALTH_DOT: Record<"healthy" | "degraded" | "unhealthy", string> = {
  healthy: "bg-emerald-400",
  degraded: "bg-amber-400",
  unhealthy: "bg-red-400",
};

export function NavLink({
  href,
  icon,
  label,
  active,
  favorited,
  onToggleFavorite,
  badgeCount,
  health,
}: {
  href: string;
  icon: string;
  label: string;
  active: boolean;
  favorited?: boolean;
  onToggleFavorite?: () => void;
  /** Live critical/high event count for this item's owning bounded context — real data only, see `liveNavBadges.ts`. */
  badgeCount?: number;
  /** Real health status (currently only populated for Runtime Health from `/api/v1/runtime/status`). */
  health?: "healthy" | "degraded" | "unhealthy";
}) {
  return (
    <div className="group/navlink flex items-center">
      <Link
        href={href}
        className={`flex flex-1 items-center gap-3 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
          active ? "bg-red-950/50 text-red-400" : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
        }`}
      >
        <span className="relative text-base">
          {icon}
          {health && (
            <span
              className={`absolute -bottom-0.5 -right-0.5 h-1.5 w-1.5 rounded-full ring-1 ring-gray-900 ${HEALTH_DOT[health]}`}
              aria-hidden="true"
            />
          )}
        </span>
        <span className="flex-1">{label}</span>
        {!!badgeCount && (
          <span
            className="rounded-full bg-red-500/90 px-1.5 py-0.5 text-[10px] font-bold leading-none text-white"
            aria-label={`${badgeCount} critical or high events`}
          >
            {badgeCount > 99 ? "99+" : badgeCount}
          </span>
        )}
      </Link>
      {onToggleFavorite && (
        <button
          type="button"
          onClick={onToggleFavorite}
          aria-label={favorited ? `Remove ${label} from favorites` : `Add ${label} to favorites`}
          className={`shrink-0 px-1.5 opacity-0 transition group-hover/navlink:opacity-100 ${
            favorited ? "opacity-100" : ""
          }`}
        >
          <Star
            className={`h-3.5 w-3.5 ${favorited ? "fill-yellow-400 text-yellow-400" : "text-gray-600"}`}
            aria-hidden="true"
          />
        </button>
      )}
    </div>
  );
}
