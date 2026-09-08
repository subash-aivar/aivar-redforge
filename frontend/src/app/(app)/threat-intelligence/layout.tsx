"use client";

/**
 * Shared shell for the M51 Native Threat Intelligence product area
 * (Slice 1). Provides one grouped sub-navigation for all nine
 * capabilities instead of crowding the primary sidebar with nine flat
 * entries — the primary sidebar carries a single "Threat Intelligence"
 * entry point (see navConfig.ts) that lands here.
 *
 * This is UX grouping only. Every link below still resolves through
 * the same backend-authoritative RBAC every M51 route already
 * enforces — nothing here decides access, it only decides what's shown.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  THREAT_INTEL_CAPABILITIES,
  THREAT_INTEL_FUTURE_SURFACES,
  THREAT_INTEL_OVERVIEW_HREF,
} from "@/lib/threatIntelShell";

function isSubNavActive(pathname: string, href: string): boolean {
  return pathname === href || pathname.startsWith(href + "/");
}

export default function ThreatIntelligenceLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();

  return (
    <div>
      <div className="mb-6 border-b border-gray-800">
        <nav
          aria-label="Threat Intelligence capabilities"
          className="-mb-px flex gap-1 overflow-x-auto whitespace-nowrap pb-px"
        >
          <TabLink
            href={THREAT_INTEL_OVERVIEW_HREF}
            label="Overview"
            icon="◎"
            active={pathname === THREAT_INTEL_OVERVIEW_HREF}
          />
          {THREAT_INTEL_CAPABILITIES.map((c) => (
            <TabLink
              key={c.key}
              href={c.href}
              label={c.label}
              icon={c.status === "live" ? "🎯" : "▢"}
              active={isSubNavActive(pathname, c.href)}
            />
          ))}
          {THREAT_INTEL_FUTURE_SURFACES.map((f) => (
            <span
              key={f.key}
              title={f.description}
              aria-disabled="true"
              className="flex shrink-0 cursor-not-allowed items-center gap-1.5 rounded-t-lg border border-transparent px-3 py-2 text-sm font-medium text-gray-700"
            >
              <span aria-hidden="true">◌</span>
              {f.label}
              <span className="rounded-full border border-gray-800 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-gray-600">
                Planned
              </span>
            </span>
          ))}
        </nav>
      </div>
      {children}
    </div>
  );
}

function TabLink({
  href,
  label,
  icon,
  active,
}: {
  href: string;
  label: string;
  icon: string;
  active: boolean;
}) {
  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      className={`flex shrink-0 items-center gap-1.5 rounded-t-lg border-b-2 px-3 py-2 text-sm font-medium transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/70 ${
        active
          ? "border-red-500 text-red-400"
          : "border-transparent text-gray-400 hover:border-gray-700 hover:text-gray-200"
      }`}
    >
      <span aria-hidden="true">{icon}</span>
      {label}
    </Link>
  );
}
