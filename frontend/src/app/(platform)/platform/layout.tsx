"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { isAuthenticated } from "@/lib/api";
import { getBootstrapStatus, getPlatformAccess, type PlatformAccess } from "@/lib/platform";

interface NavSection {
  group: string;
  items: { label: string; href: string; icon: string }[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    group: "Administration",
    items: [
      { label: "Overview", href: "/platform/overview", icon: "◎" },
      { label: "Users", href: "/platform/users", icon: "☺" },
      { label: "Organizations", href: "/platform/organizations", icon: "▦" },
      { label: "Platform Access", href: "/platform/access", icon: "🔑" },
      { label: "Audit", href: "/platform/audit", icon: "▤" },
      { label: "Security / MFA", href: "/platform/security", icon: "🔒" },
    ],
  },
  {
    group: "Threat Intelligence",
    items: [
      { label: "Reference Data", href: "/platform/threat-intel", icon: "▣" },
      { label: "Feed Management", href: "/platform/threat-intel/feeds", icon: "⇄" },
      { label: "Fusion Explorer", href: "/platform/threat-intel/fusion", icon: "❖" },
      { label: "Attack Paths", href: "/platform/threat-intel/attack-paths", icon: "⇉" },
    ],
  },
];

export default function PlatformLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [access, setAccess] = useState<PlatformAccess | null>(null);
  const [error, setError] = useState("");
  const [bootstrapConsumed, setBootstrapConsumed] = useState<boolean | null>(null);

  useEffect(() => {
    if (!isAuthenticated()) {
      router.push("/login");
      return;
    }
    // Authorization is determined ENTIRELY by the backend response to
    // GET /platform/me. Nothing in this file inspects email, username,
    // or organization role — has_platform_access is the only signal,
    // and the backend remains authoritative even if this check were
    // bypassed client-side.
    getPlatformAccess()
      .then(setAccess)
      .catch(() => setError("Failed to verify platform access."));
    getBootstrapStatus()
      .then((s) => setBootstrapConsumed(!s.available))
      .catch(() => setBootstrapConsumed(null));
  }, [router]);

  if (error) {
    return (
      <CenteredScreen>
        <div className="w-full max-w-md rounded-2xl border border-red-900/60 bg-red-950/40 p-6 text-center backdrop-blur-xl">
          <ErrorGlyph />
          <p className="mt-3 text-sm text-red-300">{error}</p>
        </div>
      </CenteredScreen>
    );
  }

  if (!access) {
    return (
      <CenteredScreen>
        <div className="flex flex-col items-center gap-3 text-gray-500">
          <PulseSpinner />
          <span className="text-sm">Verifying platform access…</span>
        </div>
      </CenteredScreen>
    );
  }

  if (!access.has_platform_access) {
    return (
      <CenteredScreen>
        <div className="w-full max-w-md rounded-2xl border border-amber-900/50 bg-amber-950/20 p-6 backdrop-blur-xl animate-fade-in-up">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-amber-400">
            <LockGlyph />
            Access Restricted
          </div>
          <p className="mt-3 text-sm font-medium text-amber-200">
            This account has no active Platform role
          </p>
          <p className="mt-2 text-xs leading-relaxed text-amber-400/70">
            Platform administration is separate from organization
            membership — an organization Owner or Admin role never grants
            platform authority. Contact an existing Platform Super
            Administrator to request access.
          </p>
          {bootstrapConsumed === false && (
            <p className="mt-3 rounded-lg border border-purple-800/50 bg-purple-950/30 px-3 py-2 text-xs text-purple-300">
              This platform has not been initialized yet — a bootstrap
              call-to-action will appear on your dashboard if this server
              recognizes your account as the initial owner.
            </p>
          )}
          <Link
            href="/dashboard"
            className="mt-4 inline-flex items-center gap-1 text-xs font-medium text-gray-400 hover:text-white"
          >
            ← Back to dashboard
          </Link>
        </div>
      </CenteredScreen>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-950">
      <aside className="flex w-64 flex-col border-r border-gray-800/80 bg-gray-900/60 backdrop-blur-xl">
        <div className="flex h-16 items-center gap-2.5 border-b border-gray-800/80 px-5">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-purple-800/60 bg-gradient-to-br from-purple-600/20 to-purple-900/20">
            <svg viewBox="0 0 24 24" className="h-4 w-4 text-purple-400" fill="none" aria-hidden="true">
              <path
                d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"
                stroke="currentColor"
                strokeWidth="1.8"
                strokeLinejoin="round"
              />
            </svg>
          </div>
          <div>
            <div className="text-sm font-bold leading-none text-white">Platform</div>
            <div className="mt-0.5 text-[10px] uppercase tracking-widest text-purple-400/70">
              Control Plane
            </div>
          </div>
        </div>

        <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
          {NAV_SECTIONS.map((section) => (
            <div key={section.group}>
              <div className="mb-1.5 px-3 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                {section.group}
              </div>
              <div className="space-y-0.5">
                {section.items.map((item) => {
                  const active =
                    pathname === item.href ||
                    (item.href !== "/platform/threat-intel" &&
                      item.href !== "/platform/overview" &&
                      pathname.startsWith(item.href + "/")) ||
                    (item.href === "/platform/threat-intel" &&
                      pathname === "/platform/threat-intel");
                  return (
                    <Link
                      key={item.href}
                      href={item.href}
                      className={`flex items-center gap-2.5 rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                        active
                          ? "bg-purple-950/60 text-purple-300 shadow-[inset_2px_0_0_0_theme(colors.purple.500)]"
                          : "text-gray-400 hover:bg-gray-800/60 hover:text-gray-200"
                      }`}
                    >
                      <span className="text-sm opacity-80">{item.icon}</span>
                      {item.label}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="border-t border-gray-800/80 px-4 py-3.5">
          <div className="flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
            <span className="text-[10px] font-semibold uppercase tracking-widest text-emerald-400">
              Session Active
            </span>
          </div>
          <div className="mt-1.5 flex flex-wrap gap-1">
            {access.platform_roles.length === 0 ? (
              <span className="text-xs text-gray-600">no roles</span>
            ) : (
              access.platform_roles.map((r) => (
                <span
                  key={r}
                  className="rounded-full border border-purple-800/60 bg-purple-950/40 px-2 py-0.5 text-[10px] font-medium text-purple-300"
                >
                  {r.replace(/_/g, " ")}
                </span>
              ))
            )}
          </div>
          <Link
            href="/dashboard"
            className="mt-2.5 block text-xs text-gray-500 transition hover:text-gray-300"
          >
            ← Back to organization dashboard
          </Link>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-7xl p-8">{children}</div>
      </main>
    </div>
  );
}

function CenteredScreen({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-6">
      {children}
    </div>
  );
}

function PulseSpinner() {
  return (
    <svg className="h-6 w-6 animate-spin text-purple-500" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" opacity="0.2" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}

function LockGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" aria-hidden="true">
      <rect x="5" y="11" width="14" height="9" rx="2" stroke="currentColor" strokeWidth="1.8" />
      <path d="M8 11V7a4 4 0 0 1 8 0v4" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}

function ErrorGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="mx-auto h-8 w-8 text-red-400" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" />
      <path d="M12 8v5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="12" cy="16" r="1" fill="currentColor" />
    </svg>
  );
}
