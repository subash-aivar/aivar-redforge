"use client";

import { useState } from "react";
import {
  AsyncContent,
  DataConsole,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  Panel,
  StatusPill,
  fmtTime,
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  closeIncident,
  getActiveDashboard,
  listIncidents,
  severityTone,
  type Incident,
} from "@/lib/incident-response";

export default function IncidentResponsePage() {
  const [tab, setTab] = useState<"active" | "history">("active");
  const dashboard = useAsync(() => getActiveDashboard(), []);
  const allIncidents = useAsync(() => listIncidents(), []);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleClose(incident: Incident) {
    const resolutionType = window.prompt(
      "Resolution type (e.g. RESOLVED, FALSE_POSITIVE, DUPLICATE):"
    );
    if (!resolutionType) return;
    setBusy(true);
    setActionError(null);
    try {
      await closeIncident(incident.incident_id, resolutionType);
      setSelected(null);
      dashboard.reload();
      allIncidents.reload();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Close failed");
    } finally {
      setBusy(false);
    }
  }

  const columns: ConsoleColumn<Incident>[] = [
    { key: "title", header: "Incident", width: "26%", render: (r) => (
      <span className="text-gray-200">{r.title}</span>
    ) },
    { key: "severity", header: "Severity", width: "12%", render: (r) => (
      <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
        severityTone(r.severity) === "critical" ? "border-red-800 bg-red-950/60 text-red-300"
        : severityTone(r.severity) === "high" ? "border-orange-800 bg-orange-950/50 text-orange-300"
        : severityTone(r.severity) === "warning" ? "border-amber-800 bg-amber-950/50 text-amber-300"
        : "border-gray-700 bg-gray-800/60 text-gray-300"
      }`}>{r.severity}</span>
    ) },
    { key: "phase", header: "Phase", width: "14%", render: (r) => <StatusPill status={r.phase} /> },
    { key: "trigger", header: "Trigger", width: "16%", render: (r) => r.trigger_type },
    { key: "classified", header: "Classified", width: "16%", render: (r) => fmtTime(r.classified_at) },
    { key: "id", header: "ID", width: "16%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-500">{r.incident_id.slice(0, 10)}…</span>
    ) },
  ];

  const historyColumns: ConsoleColumn<Incident>[] = [
    ...columns.slice(0, 3),
    { key: "closed", header: "Closed At", width: "16%", render: (r) => fmtTime(r.closed_at) },
    { key: "resolution", header: "Resolution", width: "16%", render: (r) => r.resolution_type ?? "—" },
    { key: "id", header: "ID", width: "16%", render: (r) => (
      <span className="font-mono text-[11px] text-gray-500">{r.incident_id.slice(0, 10)}…</span>
    ) },
  ];

  return (
    <>
      <PageHeader
        title="Incident Response"
        subtitle="Active incidents, containment, and closure workflow"
        actions={
          <button
            type="button"
            onClick={() => {
              dashboard.reload();
              allIncidents.reload();
            }}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <div className="mb-4 flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
        {(["active", "history"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 text-xs font-medium capitalize ${
              tab === t ? "bg-red-950/60 text-red-300" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t === "active" ? "Active Incidents" : "History (All Incidents)"}
          </button>
        ))}
      </div>

      {tab === "active" && (
        <AsyncContent state={dashboard} emptyLabel="No active incidents.">
          {(data) => (
            <>
              <div className="mb-6 grid gap-4 sm:grid-cols-3">
                <KpiTile
                  label="Active Incidents"
                  value={data.active_count}
                  tone={data.active_count > 0 ? "warning" : "ok"}
                />
                <KpiTile label="P1 (Critical)" value={data.p1_count} tone={data.p1_count > 0 ? "danger" : "ok"} />
                <KpiTile label="P2 (High)" value={data.p2_count} tone={data.p2_count > 0 ? "warning" : "ok"} />
              </div>

              <Panel title="Active Incidents">
                <DataConsole
                  columns={columns}
                  rows={data.incidents}
                  rowKey={(r) => r.incident_id}
                  onRowClick={(r) => setSelected(r)}
                  selectedKey={selected?.incident_id ?? null}
                  emptyLabel="No active incidents."
                />
              </Panel>
            </>
          )}
        </AsyncContent>
      )}

      {tab === "history" && (
        <AsyncContent state={allIncidents} emptyLabel="No incidents recorded.">
          {(rows) => {
            const closed = rows.filter((r) => r.closed_at !== null);
            const open = rows.filter((r) => r.closed_at === null);
            return (
              <>
                <div className="mb-6 grid gap-4 sm:grid-cols-3">
                  <KpiTile label="Total Incidents" value={rows.length} />
                  <KpiTile label="Closed" value={closed.length} tone="ok" />
                  <KpiTile label="Open" value={open.length} tone={open.length > 0 ? "warning" : "ok"} />
                </div>
                <Panel title="All Incidents (Active + Closed)">
                  <DataConsole
                    columns={historyColumns}
                    rows={rows}
                    rowKey={(r) => r.incident_id}
                    onRowClick={(r) => setSelected(r)}
                    selectedKey={selected?.incident_id ?? null}
                    emptyLabel="No incidents recorded."
                  />
                </Panel>
              </>
            );
          }}
        </AsyncContent>
      )}

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          setActionError(null);
        }}
        title={selected?.title ?? ""}
        subtitle={selected ? `${selected.severity} · ${selected.phase}` : undefined}
        fields={
          selected
            ? [
                { label: "Description", value: selected.description },
                { label: "Phase", value: <StatusPill status={selected.phase} /> },
                { label: "Trigger Type", value: selected.trigger_type },
                { label: "Classified At", value: fmtTime(selected.classified_at) },
                { label: "Contained At", value: fmtTime(selected.contained_at) },
                { label: "Eradicated At", value: fmtTime(selected.eradicated_at) },
                { label: "Recovered At", value: fmtTime(selected.recovered_at) },
                { label: "Closed At", value: fmtTime(selected.closed_at) },
                ...(selected.resolution_type
                  ? [{ label: "Resolution Type", value: selected.resolution_type }]
                  : []),
                ...(actionError
                  ? [{ label: "Action Error", value: <span className="text-red-400">{actionError}</span> }]
                  : []),
                ...(selected.closed_at === null
                  ? [
                      {
                        label: "Actions",
                        value: (
                          <button
                            type="button"
                            disabled={busy}
                            onClick={() => selected && handleClose(selected)}
                            className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                          >
                            Close Incident
                          </button>
                        ),
                      },
                    ]
                  : []),
              ]
            : []
        }
        links={
          selected
            ? [
                {
                  label: "View Regulatory Notifications",
                  href: `/regulatory-notification?incidentId=${encodeURIComponent(selected.incident_id)}`,
                },
                {
                  label: "View Lessons Learned",
                  href: `/lessons-learned?incidentId=${encodeURIComponent(selected.incident_id)}`,
                },
              ]
            : []
        }
      />
    </>
  );
}
