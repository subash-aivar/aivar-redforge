"use client";

import {
  AsyncContent,
  DataConsole,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  getPlatformAudit,
  listPlatformAccess,
  listPlatformOrganizations,
  listPlatformUsers,
  type PlatformAuditEntry,
} from "@/lib/platform";

export default function PlatformOverviewPage() {
  const users = useAsync(() => listPlatformUsers(), []);
  const orgs = useAsync(() => listPlatformOrganizations(), []);
  const access = useAsync(() => listPlatformAccess(), []);
  const audit = useAsync(() => getPlatformAudit(), []);

  const activeAccessCount =
    access.data?.filter((a) => a.status === "active").length ?? null;

  const columns: ConsoleColumn<PlatformAuditEntry>[] = [
    { key: "action", header: "Action", width: "24%", render: (r) => (
      <span className="font-mono text-purple-300">{r.action}</span>
    ) },
    { key: "actor", header: "Actor", width: "18%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-400">{r.actor_id.slice(0, 10)}…</span>
    ) },
    { key: "target", header: "Target", width: "18%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-400">{r.target_id.slice(0, 10)}…</span>
    ) },
    { key: "role", header: "Role", width: "14%", render: (r) => r.role ? <StatusPill status={r.role} /> : "—" },
    { key: "outcome", header: "Outcome", width: "12%", render: (r) => (
      <span className={r.outcome === "success" ? "text-emerald-400" : "text-red-400"}>
        {r.outcome}
      </span>
    ) },
    { key: "time", header: "Time", width: "14%", render: (r) => (
      <span className="text-gray-500">{fmtTime(r.timestamp)}</span>
    ) },
  ];

  return (
    <>
      <PageHeader
        title="Platform Overview"
        subtitle="Platform-wide governance metrics — not tenant security data. No organization's findings, evidence, or credentials are visible here."
        actions={
          <button
            type="button"
            onClick={() => {
              users.reload();
              orgs.reload();
              access.reload();
              audit.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-purple-700 hover:text-purple-300"
          >
            Refresh
          </button>
        }
      />

      <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-3">
        <MetricPanel label="Registered Users" state={users} accent="default" />
        <MetricPanel label="Organizations" state={orgs} accent="default" />
        <MetricPanel
          label="Active Platform Access Grants"
          state={access}
          value={activeAccessCount ?? undefined}
          accent="ok"
        />
      </div>

      <Panel
        title="Recent Platform Security Audit"
        right={
          <span className="text-[10px] uppercase tracking-widest text-gray-600">
            Append-only log
          </span>
        }
      >
        <AsyncContent state={audit} emptyLabel="No platform security events recorded yet.">
          {(rows) => (
            <DataConsole
              columns={columns}
              rows={rows.slice(0, 15)}
              rowKey={(r) => `${r.action}-${r.actor_id}-${r.target_id}-${r.timestamp}`}
              emptyLabel="No platform security events recorded yet."
            />
          )}
        </AsyncContent>
      </Panel>
    </>
  );
}

function MetricPanel({
  label,
  state,
  value,
  accent,
}: {
  label: string;
  state: { loading: boolean; error: string | null; forbidden: boolean; data: unknown[] | null };
  value?: number;
  accent: "default" | "ok";
}) {
  if (state.loading) {
    return <KpiTile label={label} value="…" />;
  }
  if (state.forbidden) {
    return <KpiTile label={label} value="—" hint="No permission" tone="warning" />;
  }
  if (state.error || state.data === null) {
    return <KpiTile label={label} value="UNAVAILABLE" tone="danger" />;
  }
  return (
    <KpiTile
      label={label}
      value={value ?? state.data.length}
      tone={accent === "ok" ? "ok" : "default"}
    />
  );
}
