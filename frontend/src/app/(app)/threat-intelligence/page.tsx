"use client";

/**
 * Native Threat Intelligence overview (M51 Slice 1 — shell only).
 *
 * Every number here comes from a real, bounded API call
 * (`listTenantIocs({ limit: 1 })` for a total count via the response's
 * `count` field, never a client-side scan of all records). If a
 * capability has no operator UI yet, its card says so honestly — no
 * fabricated count, no fake activity, no demo data.
 */
import Link from "next/link";
import { useEffect, useState } from "react";
import {
  AsyncContent,
  ForbiddenRow,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  fmtTime,
  useAsync,
  type AsyncState,
} from "@/components/cc";
import { getMe } from "@/lib/auth";
import { getEffectiveAccess } from "@/lib/rbac";
import { listTenantIocs, type PaginatedIocList } from "@/lib/iocIntelligence";
import {
  THREAT_INTEL_CAPABILITIES,
  THREAT_INTEL_FUTURE_SURFACES,
  type ThreatIntelCapability,
} from "@/lib/threatIntelShell";

export default function ThreatIntelligenceOverviewPage() {
  const [perms, setPerms] = useState<Set<string> | null>(null);

  useEffect(() => {
    getMe()
      .then((me) => getEffectiveAccess(me.user_id))
      .then((ea) => setPerms(new Set(ea.effective_permissions)))
      .catch(() => setPerms(new Set()));
  }, []);

  // The backend's own 403 on each call below is what actually decides
  // forbidden-ness, surfaced honestly through AsyncContent's
  // `state.forbidden` — this page never guesses access from `perms`
  // for the IOC panels themselves (only for the capability cards'
  // informational "No read access" hint, which is UX-only).
  const iocTotalState: AsyncState<PaginatedIocList> = useAsync(() => listTenantIocs({ limit: 1 }), []);
  const iocActiveState: AsyncState<PaginatedIocList> = useAsync(
    () => listTenantIocs({ lifecycle: "active", limit: 1 }),
    [],
  );
  const iocRecentState: AsyncState<PaginatedIocList> = useAsync(() => listTenantIocs({ limit: 5 }), []);

  return (
    <div>
      <PageHeader
        title="Threat Intelligence"
        subtitle="Native intelligence entities RedForge tracks — indicators, actors, patterns, malware, campaigns, tools, infrastructure, reports and their relationships."
      />

      <Panel title="IOC Intelligence" className="mb-6">
        {iocTotalState.forbidden ? (
          <ForbiddenRow />
        ) : (
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <AsyncContent state={iocTotalState}>
              {(d) => <KpiTile label="Tenant IOCs (total)" value={d.count} />}
            </AsyncContent>
            <AsyncContent state={iocActiveState}>
              {(d) => <KpiTile label="Active" value={d.count} tone={d.count > 0 ? "ok" : "default"} />}
            </AsyncContent>
            <div className="flex items-center">
              <Link
                href="/ioc-intelligence"
                className="rounded-lg border border-gray-800 px-4 py-2 text-sm font-medium text-gray-300 transition hover:border-red-800 hover:text-red-300"
              >
                Open IOC Intelligence →
              </Link>
            </div>
          </div>
        )}
      </Panel>

      {!iocRecentState.forbidden && (
        <Panel title="Recent IOC Activity" className="mb-6">
          <AsyncContent state={iocRecentState} empty={(d) => d.items.length === 0} emptyLabel="No IOCs observed yet.">
            {(d) => (
              <ul className="divide-y divide-gray-800">
                {d.items.map((ioc) => (
                  <li key={ioc.ioc_id} className="flex items-center justify-between gap-3 py-2 text-sm">
                    <div className="min-w-0">
                      <span className="font-mono text-gray-200">{ioc.ioc_type}</span>
                      <span className="ml-2 text-gray-500">observed {fmtTime(ioc.created_at)}</span>
                    </div>
                    <StatusPill status={ioc.lifecycle} />
                  </li>
                ))}
              </ul>
            )}
          </AsyncContent>
        </Panel>
      )}

      <Panel title="Native Intelligence Capabilities" className="mb-6">
        <p className="mb-4 text-xs text-gray-500">
          Every capability below has a certified backend (domain, persistence, API and RBAC).
          Capabilities without an operator UI yet are marked Planned — they are discoverable
          here honestly, not hidden and not faked.
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {THREAT_INTEL_CAPABILITIES.map((c) => (
            <CapabilityCard key={c.key} capability={c} perms={perms} />
          ))}
        </div>
      </Panel>

      <Panel title="Planned — Not Yet Started">
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {THREAT_INTEL_FUTURE_SURFACES.map((f) => (
            <div
              key={f.key}
              className="rounded-lg border border-dashed border-gray-800 bg-gray-900/30 p-3 opacity-70"
            >
              <div className="text-sm font-medium text-gray-400">{f.label}</div>
              <div className="mt-1 text-xs text-gray-600">{f.description}</div>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

function CapabilityCard({
  capability,
  perms,
}: {
  capability: ThreatIntelCapability;
  perms: Set<string> | null;
}) {
  const stillChecking = perms === null;
  const hasAccess = !!perms?.has(capability.tenantReadPerm);

  return (
    <Link
      href={capability.href}
      className="block rounded-lg border border-gray-800 bg-gray-900/50 p-3 transition hover:border-gray-700 hover:bg-gray-900/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-500/70"
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-sm font-medium text-gray-200">{capability.label}</span>
        {capability.status === "live" ? (
          <StatusPill status="active" />
        ) : (
          <span className="rounded-full border border-gray-800 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-gray-500">
            Planned
          </span>
        )}
      </div>
      <p className="mt-1.5 text-xs text-gray-500">{capability.description}</p>
      {!stillChecking && !hasAccess && (
        <p className="mt-2 text-[11px] font-medium text-amber-500">No read access</p>
      )}
    </Link>
  );
}
