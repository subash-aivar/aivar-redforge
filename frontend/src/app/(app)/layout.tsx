"use client";

import { usePathname, useRouter } from "next/navigation";
import { Menu } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { isAuthenticated, getOrganizationId, clearSession } from "@/lib/api";
import { getMe, getAccessibleOrganizations, logout, type UserProfile } from "@/lib/auth";
import { getPlatformAccess } from "@/lib/platform";
import { getEffectiveAccess } from "@/lib/rbac";
import { NavigationShell } from "@/components/navigation/NavigationShell";
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
