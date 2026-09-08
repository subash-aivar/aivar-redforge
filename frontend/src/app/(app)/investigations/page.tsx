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
  useAsync,
  type ConsoleColumn,
} from "@/components/cc";
import {
  acknowledgeInvestigation,
  confidenceColor,
  domainColor,
  domainLabel,
  formatTs,
  getInvestigationPosture,
  listInvestigations,
  listInvestigationAttackPaths,
  resolveInvestigation,
  severityColor,
  startInvestigation,
  statusColor,
  type InvestigationCase,
} from "@/lib/investigations";

export default function InvestigationsPage() {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const posture = useAsync(() => getInvestigationPosture(), []);
  const cases = useAsync(
    () =>
      listInvestigations({
        status: statusFilter || undefined,
        severity: severityFilter || undefined,
        limit: 100,
      }),
    [statusFilter, severityFilter]
  );
  const [selected, setSelected] = useState<InvestigationCase | null>(null);
  const [actioning, setActioning] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [attackPathCount, setAttackPathCount] = useState<number | null>(null);

  function reloadAll() {
    posture.reload();
    cases.reload();
  }

  async function openCase(c: InvestigationCase) {
    setSelected(c);
    setActionError(null);
    setAttackPathCount(null);
    try {
      const paths = await listInvestigationAttackPaths(c.id);
      setAttackPathCount(paths.length);
    } catch {
      setAttackPathCount(null);
    }
  }

  async function handleAcknowledge(caseId: string) {
    setActioning(true);
    setActionError(null);
    try {
      await acknowledgeInvestigation(caseId);
      setSelected(null);
      reloadAll();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Acknowledge failed");
    } finally {
      setActioning(false);
    }
  }

  async function handleStartInvestigation(caseId: string) {
    setActioning(true);
    setActionError(null);
    try {
      await startInvestigation(caseId);
      setSelected(null);
      reloadAll();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Start failed");
    } finally {
      setActioning(false);
    }
  }

  async function handleResolve(caseId: string) {
    const reason = window.prompt("Resolution reason:");
    if (!reason) return;
    const notes = window.prompt("Resolution notes (optional):") ?? "";
    setActioning(true);
    setActionError(null);
    try {
      await resolveInvestigation(caseId, reason, notes);
      setSelected(null);
      reloadAll();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : "Resolve failed");
    } finally {
      setActioning(false);
    }
  }

  const columns: ConsoleColumn<InvestigationCase>[] = [
    {
      key: "title",
      header: "Case",
      width: "24%",
      render: (r) => (
        <>
          <span className="text-gray-200">{r.title}</span>
          <div className="mt-0.5 max-w-xs truncate text-[11px] text-gray-500">{r.summary}</div>
        </>
      ),
    },
    { key: "status", header: "Status", width: "12%", render: (r) => (
      <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${statusColor(r.status)}`}>
        {r.status}
      </span>
    ) },
    { key: "severity", header: "Severity", width: "12%", render: (r) => (
      <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${severityColor(r.severity)}`}>
        {r.severity}
      </span>
    ) },
    { key: "confidence", header: "Confidence", width: "12%", render: (r) => (
      <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${confidenceColor(r.confidence)}`}>
        {r.confidence.replace("_", " ")}
      </span>
    ) },
    { key: "domains", header: "Domains", width: "16%", render: (r) => (
      <div className="flex flex-wrap gap-1">
        {(r.source_domains ?? []).map((d) => (
          <span key={d} className={`rounded border px-1.5 py-0.5 text-[10px] ${domainColor(d)}`}>
            {domainLabel(d)}
          </span>
        ))}
      </div>
    ) },
    { key: "evidence", header: "Evidence", width: "8%", render: (r) => r.evidence_count },
    { key: "first_observed", header: "First Observed", width: "16%", render: (r) => (
      <span className="text-[11px] text-gray-400">{formatTs(r.first_observed_at)}</span>
    ) },
  ];

  return (
    <>
      <PageHeader
        title="Unified Threat Investigation"
        subtitle="Cross-domain security cases with deterministic, explainable correlation"
        actions={
          <button
            type="button"
            onClick={reloadAll}
            className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Refresh
          </button>
        }
      />

      <AsyncContent state={posture}>
        {(p) => (
          <div className="mb-6 grid grid-cols-2 gap-4 sm:grid-cols-4 lg:grid-cols-7">
            <KpiTile label="Open" value={p.open_cases} tone={p.open_cases > 0 ? "danger" : "ok"} />
            <KpiTile label="Acknowledged" value={p.acknowledged_cases} tone={p.acknowledged_cases > 0 ? "warning" : "default"} />
            <KpiTile label="Investigating" value={p.investigating_cases} />
            <KpiTile label="Resolved" value={p.resolved_cases} tone="ok" />
            <KpiTile label="Critical" value={p.critical_cases} tone={p.critical_cases > 0 ? "danger" : "ok"} />
            <KpiTile label="High" value={p.high_cases} tone={p.high_cases > 0 ? "warning" : "default"} />
            <KpiTile label="Multi-Domain" value={p.multi_domain_cases} />
          </div>
        )}
      </AsyncContent>

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-md border border-gray-800 bg-gray-950/80 px-3 py-1.5 text-xs text-gray-300 focus:border-red-700 focus:outline-none"
        >
          <option value="">All Statuses</option>
          <option value="OPEN">Open</option>
          <option value="ACKNOWLEDGED">Acknowledged</option>
          <option value="INVESTIGATING">Investigating</option>
          <option value="RESOLVED">Resolved</option>
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-md border border-gray-800 bg-gray-950/80 px-3 py-1.5 text-xs text-gray-300 focus:border-red-700 focus:outline-none"
        >
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <AsyncContent state={cases}>
          {(rows) => (
            <span className="text-xs text-gray-500">
              {rows.length} case{rows.length !== 1 ? "s" : ""}
            </span>
          )}
        </AsyncContent>
      </div>

      <Panel title="Investigation Cases">
        <AsyncContent state={cases} emptyLabel="No investigation cases found. Cases are opened automatically when the correlation worker detects cross-domain signals.">
          {(rows) => (
            <DataConsole
              columns={columns}
              rows={rows}
              rowKey={(r) => r.id}
              onRowClick={(r) => openCase(r)}
              selectedKey={selected?.id ?? null}
              emptyLabel="No investigation cases found."
            />
          )}
        </AsyncContent>
      </Panel>

      <Panel title="About Correlation" className="mt-6">
        <div className="space-y-1.5 text-xs text-gray-400">
          <div>
            <span className="font-medium text-gray-300">Deterministic rules only</span> — no opaque AI
            scoring. Every case links to a specific rule (R01–R07) with a documented rationale.
          </div>
          <div>
            <span className="font-medium text-gray-300">Shared entity required</span> — temporal proximity
            alone never creates a case. A canonical IP address or resource ID must appear in both signals.
          </div>
          <div>
            <span className="font-medium text-gray-300">Cross-tenant isolation</span> — evidence from
            different organizations is never correlated. This invariant is enforced at every layer.
          </div>
        </div>
      </Panel>

      <InvestigationDrawer
        open={selected !== null}
        onClose={() => {
          setSelected(null);
          setActionError(null);
        }}
        title={selected?.title ?? ""}
        subtitle={selected ? `${selected.severity} · ${selected.status}` : undefined}
        entityId={selected?.id}
        fields={
          selected
            ? [
                { label: "Summary", value: selected.summary },
                { label: "Status", value: <StatusPill status={selected.status} /> },
                {
                  label: "Severity",
                  value: (
                    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${severityColor(selected.severity)}`}>
                      {selected.severity}
                    </span>
                  ),
                },
                {
                  label: "Correlation Confidence",
                  value: (
                    <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-medium ${confidenceColor(selected.confidence)}`}>
                      {selected.confidence.replace("_", " ")}
                    </span>
                  ),
                },
                {
                  label: "Source Domains",
                  value: (
                    <div className="flex flex-wrap gap-1">
                      {(selected.source_domains ?? []).map((d) => (
                        <span key={d} className={`rounded border px-1.5 py-0.5 text-[10px] ${domainColor(d)}`}>
                          {domainLabel(d)}
                        </span>
                      ))}
                    </div>
                  ),
                },
                {
                  label: "Involved Entities",
                  value:
                    selected.involved_entities.length > 0 ? (
                      <div className="space-y-0.5">
                        {selected.involved_entities.map((e, i) => (
                          <div key={i} className="font-mono text-[11px] text-gray-400">
                            {e.type}: {e.id}
                          </div>
                        ))}
                      </div>
                    ) : (
                      "—"
                    ),
                },
                { label: "Evidence Count", value: selected.evidence_count },
                { label: "First Observed", value: formatTs(selected.first_observed_at) },
                { label: "Last Observed", value: formatTs(selected.last_observed_at) },
                { label: "Opened At", value: formatTs(selected.opened_at) },
                { label: "Acknowledged At", value: formatTs(selected.acknowledged_at) },
                { label: "Investigating At", value: formatTs(selected.investigating_at) },
                { label: "Resolved At", value: formatTs(selected.resolved_at) },
                ...(selected.resolution_reason
                  ? [{ label: "Resolution Reason", value: selected.resolution_reason }]
                  : []),
                ...(selected.resolution_notes
                  ? [{ label: "Resolution Notes", value: selected.resolution_notes }]
                  : []),
                {
                  label: "Linked Attack Paths",
                  value:
                    attackPathCount === null
                      ? "—"
                      : attackPathCount === 0
                        ? "None recomputed yet"
                        : `${attackPathCount} path${attackPathCount !== 1 ? "s" : ""} linked`,
                },
                ...(actionError
                  ? [{ label: "Action Error", value: <span className="text-red-400">{actionError}</span> }]
                  : []),
                ...(selected.status !== "RESOLVED"
                  ? [
                      {
                        label: "Actions",
                        value: (
                          <div className="flex flex-wrap gap-2">
                            {selected.status === "OPEN" && (
                              <button
                                type="button"
                                disabled={actioning}
                                onClick={() => handleAcknowledge(selected.id)}
                                className="rounded-md border border-amber-800 bg-amber-950/40 px-3 py-1.5 text-xs font-semibold text-amber-300 hover:bg-amber-950/70 disabled:opacity-50"
                              >
                                Acknowledge
                              </button>
                            )}
                            {(selected.status === "OPEN" || selected.status === "ACKNOWLEDGED") && (
                              <button
                                type="button"
                                disabled={actioning}
                                onClick={() => handleStartInvestigation(selected.id)}
                                className="rounded-md border border-blue-800 bg-blue-950/40 px-3 py-1.5 text-xs font-semibold text-blue-300 hover:bg-blue-950/70 disabled:opacity-50"
                              >
                                Investigate
                              </button>
                            )}
                            <button
                              type="button"
                              disabled={actioning}
                              onClick={() => handleResolve(selected.id)}
                              className="rounded-md border border-emerald-800 bg-emerald-950/40 px-3 py-1.5 text-xs font-semibold text-emerald-300 hover:bg-emerald-950/70 disabled:opacity-50"
                            >
                              Resolve
                            </button>
                          </div>
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
                  label: "View Full Case (Timeline, Evidence, Paths)",
                  href: `/investigations/${selected.id}`,
                },
                {
                  label: "View Attack Graph",
                  href: `/attack-graph`,
                },
              ]
            : []
        }
      />
    </>
  );
}
