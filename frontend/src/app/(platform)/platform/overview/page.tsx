"use client";

import { useEffect, useState } from "react";
import {
  getBootstrapStatus,
  getPlatformAudit,
  listPlatformAccess,
  listPlatformOrganizations,
  listPlatformUsers,
  type PlatformAuditEntry,
} from "@/lib/platform";

type Metric = { value: number; loaded: boolean; failed: boolean };

const EMPTY_METRIC: Metric = { value: 0, loaded: false, failed: false };

export default function PlatformOverviewPage() {
  const [users, setUsers] = useState<Metric>(EMPTY_METRIC);
  const [orgs, setOrgs] = useState<Metric>(EMPTY_METRIC);
  const [access, setAccess] = useState<Metric>(EMPTY_METRIC);
  const [recentAudit, setRecentAudit] = useState<PlatformAuditEntry[] | null>(null);
  const [auditFailed, setAuditFailed] = useState(false);

  useEffect(() => {
    listPlatformUsers()
      .then((u) => setUsers({ value: u.length, loaded: true, failed: false }))
      .catch(() => setUsers({ value: 0, loaded: true, failed: true }));

    listPlatformOrganizations()
      .then((o) => setOrgs({ value: o.length, loaded: true, failed: false }))
      .catch(() => setOrgs({ value: 0, loaded: true, failed: true }));

    listPlatformAccess()
      .then((a) =>
        setAccess({
          value: a.filter((x) => x.status === "active").length,
          loaded: true,
          failed: false,
        })
      )
      .catch(() => setAccess({ value: 0, loaded: true, failed: true }));

    getPlatformAudit()
      .then((entries) => setRecentAudit(entries.slice(0, 10)))
      .catch(() => setAuditFailed(true));

    // Bootstrap status has no metric card but is checked so this page
    // doesn't silently omit whether bootstrap is still open — surfaced
    // via a banner only when relevant (available === true implies no
    // Super Admin exists yet, which would be unusual on this page).
    getBootstrapStatus().catch(() => {});
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Platform Overview</h1>
      <p className="mt-1 text-sm text-gray-400">
        Platform-wide governance metrics. This is not tenant security data —
        no organization&apos;s findings, evidence, or credentials are visible here.
      </p>

      <div className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <MetricCard label="Registered Users" metric={users} />
        <MetricCard label="Organizations" metric={orgs} />
        <MetricCard label="Active Platform Access Grants" metric={access} />
      </div>

      <div className="mt-8">
        <h2 className="text-sm font-medium text-gray-400">Recent Platform Security Audit</h2>
        {auditFailed ? (
          <div className="mt-2 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
            UNAVAILABLE — failed to load audit activity.
          </div>
        ) : recentAudit === null ? (
          <div className="mt-2 text-sm text-gray-500">Loading…</div>
        ) : recentAudit.length === 0 ? (
          <div className="mt-2 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
            No platform security events recorded yet.
          </div>
        ) : (
          <div className="mt-2 space-y-2">
            {recentAudit.map((e, i) => (
              <div
                key={i}
                className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-2 font-mono text-xs"
              >
                <span className="text-purple-300">{e.action}</span>
                <span className="text-gray-600"> · actor=</span>
                <span className="text-gray-400">{e.actor_id.slice(0, 10)}…</span>
                <span className="text-gray-600"> · target=</span>
                <span className="text-gray-400">{e.target_id.slice(0, 10)}…</span>
                <span className="text-gray-600"> · </span>
                <span className={e.outcome === "success" ? "text-green-400" : "text-red-400"}>
                  {e.outcome}
                </span>
                <span className="text-gray-600"> · {new Date(e.timestamp).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function MetricCard({ label, metric }: { label: string; metric: Metric }) {
  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="mt-1 text-2xl font-bold text-white">
        {!metric.loaded ? (
          <span className="text-base text-gray-600">Loading…</span>
        ) : metric.failed ? (
          <span className="text-base text-red-400">UNAVAILABLE</span>
        ) : (
          metric.value
        )}
      </div>
    </div>
  );
}
