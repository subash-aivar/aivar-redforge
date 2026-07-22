"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { isAuthenticated, getOrganizationId, clearSession } from "@/lib/api";
import { getMe, logout, type UserProfile } from "@/lib/auth";
import { getPlatformAccess } from "@/lib/platform";
import { getEffectiveAccess } from "@/lib/rbac";

// Each item may declare a `perm`: the effective permission required to
// SEE it in the nav. Items with no `perm` are always shown (they either
// have no single gating permission or are self-service). Nav visibility
// is UX-only — the backend independently enforces every route, and each
// page renders a clean permission-denied state on a direct 403.
interface NavItem {
  label: string;
  href: string;
  icon: string;
  perm?: string;
}
interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Command Center",
    items: [
      { label: "Overview", href: "/command-center", icon: "◎", perm: "security_operations:read" },
      { label: "Live Security", href: "/security-operations", icon: "⌘", perm: "security_operations:read" },
      { label: "Behavior Analytics", href: "/command-center/behavior", icon: "🧭", perm: "security_operations:read" },
      { label: "Threat Intelligence", href: "/command-center/intelligence", icon: "🛡", perm: "security_operations:read" },
      { label: "Attack Paths", href: "/attack-paths", icon: "⇉", perm: "security_operations:read" },
      { label: "Findings", href: "/findings", icon: "⚠", perm: "findings:read" },
      { label: "Risk", href: "/risk", icon: "△" },
    ],
  },
  {
    title: "Assets & Network",
    items: [
      { label: "Asset Inventory", href: "/assets", icon: "▦" },
      { label: "Network Map", href: "/command-center/map", icon: "◈", perm: "security_operations:read" },
      { label: "Geo Security Map", href: "/command-center/geo-map", icon: "🌍", perm: "security_operations:read" },
      { label: "Firewall / IDS Wall", href: "/command-center/firewall", icon: "⛨", perm: "network_security:read" },
      { label: "Network Security", href: "/network-security", icon: "🛰", perm: "network_security:read" },
      { label: "Network Exposure", href: "/command-center/exposure", icon: "⌁", perm: "network_security:read" },
      { label: "DMZ & Zones", href: "/command-center/zones", icon: "▛", perm: "network_security:read" },
      { label: "Cloud Security", href: "/cloud-security", icon: "☁" },
      { label: "Connectors", href: "/connectors", icon: "⇄" },
      { label: "Targets", href: "/targets", icon: "⬡" },
    ],
  },
  {
    title: "Behavioral NDR",
    items: [
      { label: "NDR Operations Center", href: "/behavior", icon: "⬡", perm: "behavior:read" },
      { label: "Live Detections", href: "/behavior/detections", icon: "◈", perm: "behavior:read" },
      { label: "Entity Risk", href: "/behavior/entities", icon: "◉", perm: "behavior:read" },
      { label: "Network Graph", href: "/behavior/network", icon: "⬡", perm: "behavior:read" },
    ],
  },
  {
    title: "DDoS Defense",
    items: [
      { label: "DDoS Overview", href: "/ddos", icon: "⛨", perm: "ddos:read" },
      { label: "Active Incidents", href: "/ddos/incidents", icon: "⚡", perm: "ddos:read" },
      { label: "Traffic Analytics", href: "/ddos/traffic", icon: "〰", perm: "ddos:read" },
      { label: "Protected Resources", href: "/ddos/protected-resources", icon: "▣", perm: "ddos:manage" },
      { label: "Mitigation Center", href: "/ddos/mitigation", icon: "🛡", perm: "ddos:mitigation_approve" },
    ],
  },
  {
    title: "Investigation",
    items: [
      { label: "Investigations", href: "/investigations", icon: "⊕", perm: "investigations:read" },
      { label: "Incident Response", href: "/incident-response", icon: "🚨", perm: "incident:read" },
      { label: "Compliance", href: "/compliance", icon: "▣", perm: "compliance:read" },
    ],
  },
  {
    title: "Detection & Response",
    items: [
      { label: "Exposure Management", href: "/exposure-management", icon: "◉" },
      { label: "Attack Surface", href: "/attack-surface", icon: "◆" },
      { label: "Security Graph", href: "/security-graph", icon: "❖" },
      { label: "Identity Security", href: "/identity-security", icon: "⚑" },
      { label: "Identities", href: "/identities", icon: "☺" },
      { label: "Directory Groups", href: "/directory-groups", icon: "▤" },
      { label: "Campaigns", href: "/campaigns", icon: "⚔" },
      { label: "Validation Operations", href: "/validation-operations", icon: "✓" },
      { label: "Continuous Validation", href: "/continuous-validation", icon: "↻" },
      { label: "Authorization", href: "/authorization", icon: "🔒" },
      { label: "Threat Hunt", href: "/threat-hunt", icon: "🎯", perm: "threat_hunt:read" },
      { label: "Playbooks", href: "/playbooks", icon: "▶", perm: "playbooks:read" },
    ],
  },
  {
    title: "Monitoring",
    items: [
      { label: "Integrations", href: "/command-center/integrations", icon: "🔌", perm: "security_operations:read" },
      { label: "Network Exposure (legacy)", href: "/network-exposure", icon: "⌗" },
      { label: "Runtime Health", href: "/health", icon: "♥" },
    ],
  },
  {
    title: "Analytics & AI Governance",
    items: [
      { label: "Analytics", href: "/analytics", icon: "📊", perm: "analytics:read" },
    ],
  },
  {
    title: "Administration",
    items: [
      { label: "Roles & Permissions", href: "/roles", icon: "🛡", perm: "roles:read" },
      { label: "Groups", href: "/groups-rbac", icon: "◫", perm: "groups:read" },
      { label: "Access Explorer", href: "/access-explorer", icon: "🔍" },
    ],
  },
];

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [hasPlatformAccess, setHasPlatformAccess] = useState(false);
  // null = not yet loaded → fail-open (show everything); a Set once loaded.
  const [perms, setPerms] = useState<Set<string> | null>(null);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }
    if (!getOrganizationId()) {
      router.push("/org-select");
      return;
    }
    getMe()
      .then((me) => {
        setUser(me);
        // Fetch the caller's OWN effective permissions (self-service) to
        // drive nav visibility. On any failure, leave perms null =
        // fail-open; the backend still enforces every route.
        getEffectiveAccess(me.user_id)
          .then((ea) => setPerms(new Set(ea.effective_permissions)))
          .catch(() => setPerms(null));
      })
      .catch(() => {
        clearSession();
        router.push("/login");
      });
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

  const can = (perm?: string) => !perm || perms === null || perms.has(perm);

  return (
    <div className="flex min-h-screen bg-gray-950">
      <aside className="flex w-60 flex-col border-r border-gray-800 bg-gray-900">
        <div className="flex h-14 items-center border-b border-gray-800 px-5">
          <span className="text-lg font-bold text-red-500">RedForge</span>
        </div>
        <nav className="flex-1 space-y-4 overflow-y-auto px-3 py-4">
          {NAV_GROUPS.map((group) => {
            const items = group.items.filter((i) => can(i.perm));
            if (items.length === 0) return null;
            return (
              <div key={group.title}>
                <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                  {group.title}
                </div>
                <div className="space-y-0.5">
                  {items.map((item) => {
                    const active =
                      pathname === item.href ||
                      (item.href !== "/command-center" && pathname.startsWith(item.href + "/")) ||
                      (item.href === "/command-center" && pathname === "/command-center");
                    return (
                      <Link
                        key={item.href}
                        href={item.href}
                        className={`flex items-center gap-3 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
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
                </div>
              </div>
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

      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-7xl p-6">{children}</div>
      </main>
    </div>
  );
}
