"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { isAuthenticated } from "@/lib/api";
import { getPlatformAccess, type PlatformAccess } from "@/lib/platform";

const NAV = [
  { label: "Overview", href: "/platform/overview" },
  { label: "Users", href: "/platform/users" },
  { label: "Organizations", href: "/platform/organizations" },
  { label: "Platform Access", href: "/platform/access" },
  { label: "Audit", href: "/platform/audit" },
  { label: "Security / MFA", href: "/platform/security" },
];

export default function PlatformLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [access, setAccess] = useState<PlatformAccess | null>(null);
  const [error, setError] = useState("");

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
  }, [router]);

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="max-w-md rounded-xl border border-red-800 bg-red-950 p-6 text-center text-red-300">
          {error}
        </div>
      </div>
    );
  }

  if (!access) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="text-gray-400">Checking platform access…</div>
      </div>
    );
  }

  if (!access.has_platform_access) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="max-w-md rounded-xl border border-yellow-800 bg-yellow-950 p-6 text-center">
          <p className="text-yellow-300 font-medium">No platform access</p>
          <p className="mt-2 text-sm text-yellow-400/80">
            This account has no active platform role. Platform administration is
            separate from organization membership — an organization Owner or
            Admin role does not grant platform access.
          </p>
          <Link
            href="/dashboard"
            className="mt-4 inline-block text-sm text-gray-400 hover:text-white"
          >
            Back to dashboard
          </Link>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-950">
      <aside className="flex w-60 flex-col border-r border-gray-800 bg-gray-900">
        <div className="flex h-14 items-center border-b border-gray-800 px-5">
          <span className="text-lg font-bold text-purple-400">Platform</span>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-4">
          {NAV.map((item) => {
            const active = pathname.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`block rounded-lg px-3 py-2 text-sm font-medium transition ${
                  active
                    ? "bg-purple-950/50 text-purple-300"
                    : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>
        <div className="border-t border-gray-800 px-4 py-3">
          <div className="text-xs text-gray-500">Platform roles</div>
          <div className="mt-1 text-xs text-purple-300">
            {access.platform_roles.join(", ") || "none"}
          </div>
          <Link
            href="/dashboard"
            className="mt-2 block text-xs text-gray-500 hover:text-gray-300"
          >
            ← Back to organization dashboard
          </Link>
        </div>
      </aside>
      <main className="flex-1 overflow-auto">
        <div className="mx-auto max-w-6xl p-6">{children}</div>
      </main>
    </div>
  );
}
