"use client";

import { usePathname, useRouter } from "next/navigation";
import { Menu } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { isAuthenticated, getOrganizationId, clearSession } from "@/lib/api";
import { getMe, getAccessibleOrganizations, logout, type UserProfile } from "@/lib/auth";
import { getPlatformAccess } from "@/lib/platform";
import { getEffectiveAccess } from "@/lib/rbac";
import { NavigationShell } from "@/components/navigation/NavigationShell";
import { getProductEdition } from "@/lib/productEdition";
import { detectEditionMismatch, editionMismatchDiagnostic } from "@/lib/editionMismatch";
import { getRuntimeStatus } from "@/lib/runtime";
import { Breadcrumb } from "@/components/navigation/Breadcrumb";
import { NotificationCenter } from "@/components/navigation/NotificationCenter";
import { EventBusProvider } from "@/components/platform/EventBusProvider";
import { GlobalStatusBar } from "@/components/platform/GlobalStatusBar";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [user, setUser] = useState<UserProfile | null>(null);
  const [hasPlatformAccess, setHasPlatformAccess] = useState(false);
  // null = not yet loaded → fail-open (show everything); a Set once loaded.
  const [perms, setPerms] = useState<Set<string> | null>(null);
  const [organizationName, setOrganizationName] = useState<string | null>(null);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const mobileNavTriggerRef = useRef<HTMLButtonElement>(null);
  // ADR-0009: frontend<->backend product_edition consistency. Config
  // integrity only — never widens or narrows backend route access,
  // which the backend alone decides from its own `Settings`. `null` =
  // not yet checked (don't block render on a slow/failed health call);
  // an explicit mismatch blocks the normal app shell in favor of a
  // clear operator-facing error below.
  const [editionMismatch, setEditionMismatch] = useState<
    ReturnType<typeof detectEditionMismatch> | null
  >(null);

  useEffect(() => {
    getRuntimeStatus()
      .then((status) => {
        const info = detectEditionMismatch(getProductEdition(), status.product_edition);
        if (info.mismatched) {
          // Structured, secret-free diagnostic only (two edition
          // strings) — no env dump, no tokens, no settings object.
          // eslint-disable-next-line no-console
          console.error(editionMismatchDiagnostic(info));
        }
        setEditionMismatch(info);
      })
      .catch(() => {
        // Runtime status unreachable — fail open on the mismatch
        // check itself (this is a config-integrity nicety, not the
        // security boundary); normal auth/RBAC flow still applies.
        setEditionMismatch(null);
      });
  }, []);

  // Route change (including browser back/forward) never leaves a
  // stale open drawer behind.
  useEffect(() => {
    setMobileNavOpen(false);
  }, [pathname]);

  function closeMobileNav() {
    setMobileNavOpen(false);
    mobileNavTriggerRef.current?.focus();
  }

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
    const currentOrgId = getOrganizationId();
    if (currentOrgId) {
      getAccessibleOrganizations()
        .then((orgs) => setOrganizationName(orgs.find((o) => o.id === currentOrgId)?.name ?? null))
        .catch(() => setOrganizationName(null));
    }
  }, [router]);

  if (!user) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="text-gray-400">Loading...</div>
      </div>
    );
  }

  if (editionMismatch?.mismatched) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950 p-6">
        <div
          role="alert"
          className="max-w-lg rounded-lg border border-red-800 bg-red-950/40 p-6 text-center"
        >
          <div className="text-lg font-semibold text-red-300">
            Configuration error: product edition mismatch
          </div>
          <p className="mt-3 text-sm text-gray-300">
            This frontend was built for the{" "}
            <span className="font-mono text-red-300">{editionMismatch.frontendEdition}</span>{" "}
            edition, but the backend it is connected to reports the{" "}
            <span className="font-mono text-red-300">{editionMismatch.backendEdition}</span>{" "}
            edition.
          </p>
          <p className="mt-2 text-sm text-gray-400">
            Rebuild the frontend for the backend&apos;s edition, or point it at a backend
            running the same edition. See ADR-0009.
          </p>
        </div>
      </div>
    );
  }

  const can = (perm?: string) => !perm || perms === null || perms.has(perm);

  return (
    <EventBusProvider>
      <div className="flex min-h-screen bg-gray-950">
        <NavigationShell
          pathname={pathname}
          can={can}
          hasPlatformAccess={hasPlatformAccess}
          user={user}
          onSwitchOrg={() => router.push("/org-select")}
          onSignOut={logout}
          mobileOpen={mobileNavOpen}
          onCloseMobile={closeMobileNav}
          edition={getProductEdition()}
        />

        <div className="flex flex-1 flex-col overflow-hidden">
          <GlobalStatusBar organizationName={organizationName} />
          <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b border-gray-800 bg-gray-950 px-6">
            <div className="flex min-w-0 items-center gap-3">
              <button
                ref={mobileNavTriggerRef}
                type="button"
                onClick={() => setMobileNavOpen(true)}
                aria-label="Open navigation"
                aria-expanded={mobileNavOpen}
                aria-controls="app-mobile-nav"
                className="rounded-md border border-gray-800 p-1.5 text-gray-400 hover:text-gray-200 md:hidden"
              >
                <Menu className="h-4 w-4" aria-hidden="true" />
              </button>
              <Breadcrumb pathname={pathname} />
            </div>
            <NotificationCenter />
          </header>
          <main className="flex-1 overflow-auto">
            <div className="mx-auto max-w-7xl p-6">{children}</div>
          </main>
        </div>
      </div>
    </EventBusProvider>
  );
}
