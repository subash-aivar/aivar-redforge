"use client";

/**
 * Honest placeholder for a certified M51 backend capability that has no
 * operator UI yet (M51 Slice 1 scope: shell only — implementing the
 * eight remaining vertical pages is explicitly out of scope for this
 * slice). Never fabricates data, counts, or activity. Still checks the
 * caller's real permission for this capability so a user without access
 * sees a genuine permission-denied state rather than a uniform "coming
 * soon" — the one honest signal this page can give before any API for
 * this capability exists to enforce it.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { ForbiddenRow, LoadingRow, PageHeader, Panel } from "@/components/cc";
import { getMe } from "@/lib/auth";
import { getEffectiveAccess } from "@/lib/rbac";
import { THREAT_INTEL_OVERVIEW_HREF, type ThreatIntelCapability } from "@/lib/threatIntelShell";

export function ComingSoon({ capability }: { capability: ThreatIntelCapability }) {
  const [perms, setPerms] = useState<Set<string> | null>(null);
  const [checkFailed, setCheckFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getMe()
      .then((me) => getEffectiveAccess(me.user_id))
      .then((ea) => {
        if (!cancelled) setPerms(new Set(ea.effective_permissions));
      })
      .catch(() => {
        if (!cancelled) setCheckFailed(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const stillChecking = perms === null && !checkFailed;
  const hasAccess = perms !== null && perms.has(capability.tenantReadPerm);

  return (
    <div>
      <PageHeader
        title={capability.label}
        subtitle={capability.description}
        actions={
          <Link
            href={THREAT_INTEL_OVERVIEW_HREF}
            className="rounded-lg border border-gray-800 px-3 py-1.5 text-xs font-medium text-gray-400 transition hover:border-gray-700 hover:text-gray-200"
          >
            ← Threat Intelligence overview
          </Link>
        }
      />
      <Panel>
        {stillChecking ? (
          <LoadingRow label="Checking access…" />
        ) : !hasAccess ? (
          <ForbiddenRow />
        ) : (
          <div className="flex flex-col items-center justify-center rounded-lg border border-dashed border-gray-700 bg-gray-900/40 px-4 py-10 text-center">
            <div className="text-xs font-semibold uppercase tracking-widest text-gray-500">
              Backend Certified — Operator UI Not Yet Built
            </div>
            <p className="mt-3 max-w-md text-sm text-gray-400">
              The <span className="font-medium text-gray-300">{capability.label}</span>{" "}
              intelligence backend is live and enforced (domain, persistence, API and RBAC
              all certified). This release does not yet include an operator interface for
              it. No data is shown here because none has been built to show — not because
              none exists.
            </p>
            <p className="mt-3 text-[11px] text-gray-600">
              You have read access to this capability. It will appear here once its
              operator UI ships in a future M51 slice.
            </p>
          </div>
        )}
      </Panel>
    </div>
  );
}
