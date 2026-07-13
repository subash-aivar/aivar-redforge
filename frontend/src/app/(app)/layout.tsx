"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { isAuthenticated, getOrganizationId, clearSession } from "@/lib/api";
import { getMe, logout, type UserProfile } from "@/lib/auth";
import { getPlatformAccess } from "@/lib/platform";

const NAV = [
  { label: "Dashboard", href: "/dashboard", icon: "◉" },
  { label: "Security Operations", href: "/security-operations", icon: "⌘" },
  { label: "Targets", href: "/targets", icon: "⬡" },
  { label: "Assets", href: "/assets", icon: "▦" },
  { label: "Connectors", href: "/connectors", icon: "⇄" },
  { label: "Identities", href: "/identities", icon: "☺" },
  { label: "Directory Groups", href: "/directory-groups", icon: "▤" },
  { label: "Identity Security", href: "/identity-security", icon: "⚑" },
  { label: "Network Exposure", href: "/network-exposure", icon: "⌁" },
  { label: "Network Security", href: "/network-security", icon: "🛰" },
  { label: "Cloud Security", href: "/cloud-security", icon: "☁" },
  { label: "Exposure Management", href: "/exposure-management", icon: "◎" },
  { label: "Attack Surface", href: "/attack-surface", icon: "◆" },
  { label: "Security Graph", href: "/security-graph", icon: "◈" },
  { label: "Campaigns", href: "/campaigns", icon: "⚔" },
  { label: "Findings", href: "/findings", icon: "⚠" },
  { label: "Authorization", href: "/authorization", icon: "🔒" },
  { label: "Validation Operations", href: "/validation-operations", icon: "✓" },
  { label: "Continuous Validation", href: "/continuous-validation", icon: "↻" },
  { label: "Risk", href: "/risk", icon: "△" },
  { label: "Health", href: "/health", icon: "♥" },
  { label: "Roles & Permissions", href: "/roles", icon: "🛡" },
  { label: "Groups", href: "/groups-rbac", icon: "◫" },
  { label: "Access Explorer", href: "/access-explorer", icon: "🔍" },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [hasPlatformAccess, setHasPlatformAccess] = useState(false);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }
    // If no org is selected yet, send to org-select.
    if (!getOrganizationId()) {
      router.push("/org-select");
      return;
    }
    getMe().then(setUser).catch(() => {
      // An invalid/expired token must never linger — otherwise every
      // subsequent page load reads isAuthenticated()=true, skips the
      // login redirect's own token check, and can only fail the exact
      // same way again on next render.
      clearSession();
      router.push("/login");
    });
    // Platform link visibility is determined ENTIRELY by the backend's
    // has_platform_access response — never by email/username/org role.
    // This is UX only; /platform's own layout re-verifies server-side.
    getPlatformAccess()
      .then((access) => setHasPlatformAccess(access.has_platform_access))
      .catch(() => setHasPlatformAccess(false));
  }, [router]);

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="text-gray-400">Loading...</div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-950">
      {/* Sidebar */}
      <aside className="flex w-60 flex-col border-r border-gray-800 bg-gray-900">
        <div className="flex h-14 items-center border-b border-gray-800 px-5">
          <span className="text-lg font-bold text-red-500">RedForge</span>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-4">
          {NAV.map((item) => {
            const active = pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition ${
                  active
                    ? "bg-red-950/50 text-red-400"
                    : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                }`}
              >
                <span className="text-base">{item.icon}</span>
                {item.label}
              </Link>
            );
          })}
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
            onClick={() => router.push("/org-select")}
            className="mt-1 text-xs text-gray-500 hover:text-gray-300"
          >
            Switch org
          </button>
          <button
            onClick={logout}
            className="mt-1 block text-xs text-gray-500 hover:text-red-400"
          >
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-7xl p-6">{children}</div>
      </main>
    </div>
  );
}
