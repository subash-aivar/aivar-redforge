"use client";

import Link from "next/link";
import { useEffect, useMemo, useState } from "react";
import { getSummary, type SecurityOperationsSummary, type OperationalEvent } from "@/lib/securityOperations";
import { useSecurityOperationsStream } from "@/lib/useSecurityOperationsStream";
import { getCommandOverview, ZONE_LABELS } from "@/lib/commandCenter";
import { listSecurityConditions, type SecurityCondition } from "@/lib/securityConditions";
import { listSecurityCorrelations, type SecurityCorrelation } from "@/lib/securityCorrelations";
import { getNetworkDrift, type NetworkDriftEvent } from "@/lib/commandCenter";
import {
  AsyncContent,
  DataConsole,
  FilterChip,
  GlobalSecurityStrip,
  InvestigationDrawer,
  KpiTile,
  MiniBars,
  Panel,
  PageHeader,
  PauseResumeButton,
  PostureGauge,
  SearchInput,
  SeverityBadge,
  fmtTime,
  useAsync,
  type DrawerField,
  type StripMetric,
} from "@/components/cc";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "#f87171",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  info: "#9ca3af",
  unknown: "#a78bfa",
};

const CONSOLE_SEVERITIES = ["critical", "high", "warning", "notice", "info"] as const;

interface AlertRow {
  kind: "condition" | "correlation" | "drift";
  id: string;
  severity: string | null;
  title: string;
  detail: string;
  occurredAt: string;
  raw: SecurityCondition | SecurityCorrelation | NetworkDriftEvent;
}

async function loadAlertQueue(): Promise<AlertRow[]> {
  const [conditions, correlations, drift] = await Promise.all([
    listSecurityConditions({ lifecycle: "active", limit: 200 }),
    listSecurityCorrelations({ lifecycle: "active", limit: 200 }),
    getNetworkDrift(50),
  ]);
  const rows: AlertRow[] = [
    ...conditions.map((c): AlertRow => ({
      kind: "condition",
      id: c.id,
      severity: c.severity,
      title: c.title,
      detail: c.summary,
      occurredAt: c.last_observed_at,
      raw: c,
    })),
    ...correlations.map((c): AlertRow => ({
      kind: "correlation",
      id: c.id,
      severity: null,
      title: c.title,
      detail: c.summary,
      occurredAt: c.last_observed_at,
      raw: c,
    })),
    ...drift.map((d): AlertRow => ({
      kind: "drift",
      id: d.id,
      severity: d.severity,
      title: d.summary,
      detail: d.target_asset_name ? `Target: ${d.target_asset_name}` : "",
      occurredAt: d.detected_at,
      raw: d,
    })),
  ];
  rows.sort((a, b) => (a.occurredAt < b.occurredAt ? 1 : -1));
  return rows;
}

export default function CommandCenterOverviewPage() {
  const overview = useAsync(getCommandOverview, []);
  const summary = useAsync<SecurityOperationsSummary>(() => getSummary("24h"), []);
  const alerts = useAsync(loadAlertQueue, []);
  const stream = useSecurityOperationsStream(true);

  // ── Live Security Activity Console state ──────────────────────────────
  const [paused, setPaused] = useState(false);
  const [frozenEvents, setFrozenEvents] = useState<OperationalEvent[]>([]);
  const [severityFilter, setSeverityFilter] = useState<Set<string>>(new Set());
  const [domainFilter, setDomainFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<OperationalEvent | null>(null);
  const [selectedAlert, setSelectedAlert] = useState<AlertRow | null>(null);

  useEffect(() => {
    if (!paused) setFrozenEvents(stream.events);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stream.events, paused]);

  const liveEvents = paused ? frozenEvents : stream.events;
  const domains = useMemo(
    () => Array.from(new Set(liveEvents.map((e) => e.source_domain))).sort(),
    [liveEvents]
  );
  const filteredEvents = useMemo(() => {
    return [...liveEvents]
      .reverse()
      .filter((e) => severityFilter.size === 0 || severityFilter.has(e.importance))
      .filter((e) => !domainFilter || e.source_domain === domainFilter)
      .filter(
        (e) =>
          !search ||
          e.title.toLowerCase().includes(search.toLowerCase()) ||
          e.summary.toLowerCase().includes(search.toLowerCase())
      )
      .slice(0, 100);
  }, [liveEvents, severityFilter, domainFilter, search]);

  function toggleSeverity(s: string) {
    setSeverityFilter((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  // ── Alert Queue severity counts (never a client fabrication — counts
  // are computed here purely from already-fetched real rows, same as any
  // client-side aggregation of a fetched dataset) ─────────────────────────
  const alertCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const a of alerts.data ?? []) {
      const key = a.severity ?? "correlation";
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return counts;
  }, [alerts.data]);

  const stripMetrics: StripMetric[] = overview.data
    ? [
        {
          label: "Critical",
          value: overview.data.active_conditions_by_severity.critical ?? 0,
          tone: "critical",
        },
        {
          label: "High",
          value: overview.data.active_conditions_by_severity.high ?? 0,
          tone: "high",
        },
        {
          label: "Correlations",
          value: overview.data.active_correlation_count,
          tone: overview.data.active_correlation_count > 0 ? "warning" : "ok",
        },
        {
          label: "Drift (24h)",
          value: summary.data?.drift_events_in_period ?? 0,
          tone: (summary.data?.drift_events_in_period ?? 0) > 0 ? "warning" : "ok",
        },
        {
          label: "Monitored assets",
          value: overview.data.total_assets,
          tone: "neutral",
        },
        {
          label: "Validation running",
          value: overview.data.validation_run_counts.running ?? 0,
          tone: "neutral",
        },
        {
          label: "Runtime degraded",
          value: summary.data?.runtime_unhealthy_components ?? 0,
          tone: (summary.data?.runtime_unhealthy_components ?? 0) > 0 ? "critical" : "ok",
        },
        {
          label: "Posture",
          value: overview.data.posture_score,
          tone:
            overview.data.posture_band === "critical"
              ? "critical"
              : overview.data.posture_band === "at_risk"
                ? "warning"
                : "ok",
        },
      ]
    : [];

  const eventDrawerFields: DrawerField[] = selectedEvent
    ? [
        { label: "Title", value: selectedEvent.title },
        { label: "Summary", value: selectedEvent.summary || "—" },
        { label: "Source domain", value: selectedEvent.source_domain },
        { label: "Importance", value: <SeverityBadge severity={selectedEvent.importance} /> },
        { label: "Entity type", value: selectedEvent.entity_type },
        { label: "Entity ID", value: selectedEvent.entity_id },
        { label: "Occurred at", value: fmtTime(selectedEvent.occurred_at) },
        { label: "Event ID", value: selectedEvent.event_id },
        { label: "Cursor", value: <span className="font-mono text-[11px]">{selectedEvent.cursor}</span> },
      ]
    : [];

  const alertDrawerFields: DrawerField[] = selectedAlert
    ? (() => {
        if (selectedAlert.kind === "condition") {
          const c = selectedAlert.raw as SecurityCondition;
          return [
            { label: "Title", value: c.title },
            { label: "Summary", value: c.summary },
            { label: "Severity", value: <SeverityBadge severity={c.severity} /> },
            { label: "Source category", value: c.source_category },
            { label: "Stable rule", value: c.stable_rule_id },
            { label: "Evidence state", value: c.evidence_state },
            { label: "Lifecycle", value: c.lifecycle },
            { label: "Qualifier", value: c.qualifier || "—" },
            { label: "Affected asset", value: c.affected_asset_id },
            { label: "Remediation", value: c.remediation || "—" },
            { label: "First observed", value: fmtTime(c.first_observed_at) },
            { label: "Last observed", value: fmtTime(c.last_observed_at) },
          ];
        }
        if (selectedAlert.kind === "correlation") {
          const c = selectedAlert.raw as SecurityCorrelation;
          return [
            { label: "Title", value: c.title },
            { label: "Summary", value: c.summary },
            { label: "Stable rule", value: c.stable_rule_id },
            { label: "Rule version", value: c.rule_version },
            { label: "Evidence state", value: c.evidence_state },
            { label: "Lifecycle", value: c.lifecycle },
            { label: "Operator action", value: c.operator_action || "—" },
            { label: "Linked assets", value: c.entity_ids.join(", ") || "—" },
            { label: "Linked conditions", value: c.condition_ids.join(", ") || "—" },
            { label: "First observed", value: fmtTime(c.first_observed_at) },
            { label: "Last observed", value: fmtTime(c.last_observed_at) },
          ];
        }
        const d = selectedAlert.raw as NetworkDriftEvent;
        return [
          { label: "Category", value: d.category },
          { label: "Summary", value: d.summary },
          { label: "Severity", value: <SeverityBadge severity={d.severity} /> },
          { label: "Target asset", value: d.target_asset_name || d.target_asset_id || "—" },
          { label: "Policy", value: d.policy_id },
          { label: "Run", value: d.run_id },
          { label: "Detected at", value: fmtTime(d.detected_at) },
        ];
      })()
    : [];

  return (
    <div>
      <PageHeader
        title="Security Operations Command Center"
        subtitle="Live, evidence-backed operational picture across identity, network, validation, and runtime. Every value traces to a real record."
        actions={
          <span className="text-xs text-gray-500">
            feed: <span className="text-gray-300">{stream.connectionState}</span>
          </span>
        }
      />

      <GlobalSecurityStrip metrics={stripMetrics} />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        {/* Live Security Activity Console */}
        <Panel
          title="Live security activity console"
          className="xl:col-span-2"
          right={
            <div className="flex items-center gap-2">
              <PauseResumeButton paused={paused} onToggle={() => setPaused((p) => !p)} />
              <Link href="/security-operations" className="text-[11px] text-red-400 hover:text-red-300">
                full feed →
              </Link>
            </div>
          }
        >
          <div className="mb-3 flex flex-wrap items-center gap-2">
            {CONSOLE_SEVERITIES.map((s) => (
              <FilterChip
                key={s}
                label={s}
                active={severityFilter.has(s)}
                onClick={() => toggleSeverity(s)}
                tone={s === "critical" ? "critical" : s === "high" ? "high" : s === "warning" ? "warning" : "neutral"}
              />
            ))}
            <span className="mx-1 h-4 w-px bg-gray-800" />
            {domains.map((d) => (
              <FilterChip
                key={d}
                label={d.replace(/_/g, " ")}
                active={domainFilter === d}
                onClick={() => setDomainFilter((cur) => (cur === d ? null : d))}
              />
            ))}
            <span className="ml-auto">
              <SearchInput value={search} onChange={setSearch} placeholder="Search title/summary…" />
            </span>
          </div>
          <DataConsole
            rows={filteredEvents}
            rowKey={(e) => e.cursor}
            onRowClick={setSelectedEvent}
            selectedKey={selectedEvent?.cursor ?? null}
            emptyLabel={
              liveEvents.length === 0
                ? `Listening for operational events… (${stream.connectionState})`
                : "No events match the current filters."
            }
            columns={[
              { key: "sev", header: "Sev", width: "70px", render: (e) => <SeverityBadge severity={e.importance} /> },
              { key: "domain", header: "Domain", width: "130px", render: (e) => e.source_domain },
              { key: "title", header: "Event", render: (e) => <span className="text-gray-200">{e.title}</span> },
              { key: "entity", header: "Entity", width: "140px", render: (e) => e.entity_type },
              { key: "time", header: "Occurred", width: "150px", render: (e) => fmtTime(e.occurred_at) },
            ]}
          />
        </Panel>

        {/* Posture */}
        <Panel title="Security posture">
          <AsyncContent state={overview}>
            {(o) => (
              <div>
                <div className="flex justify-center">
                  <PostureGauge score={o.posture_score} band={o.posture_band} />
                </div>
                <div className="mt-2 text-center text-[11px] text-gray-600">
                  Deterministic formula v{o.posture_formula_version} · deduction {o.posture_total_deduction}
                </div>
                <div className="mt-3 space-y-1">
                  {o.posture_contributions.length === 0 ? (
                    <div className="text-center text-xs text-gray-500">No active findings deduct from posture.</div>
                  ) : (
                    o.posture_contributions.map((c) => (
                      <div key={c.factor} className="flex justify-between text-xs text-gray-400">
                        <span>{c.factor.replace(/_/g, " ")}</span>
                        <span className="tabular-nums text-gray-300">
                          {c.count} × {c.weight} = −{c.deduction}
                        </span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      {/* Security Alert Queue */}
      <div className="mt-4">
        <Panel
          title="Security alert queue"
          right={
            <div className="flex items-center gap-1.5">
              {Object.entries(alertCounts).map(([sev, count]) => (
                <span key={sev} className="flex items-center gap-1">
                  <SeverityBadge severity={sev === "correlation" ? "info" : sev} />
                  <span className="text-[11px] tabular-nums text-gray-400">{count}</span>
                </span>
              ))}
            </div>
          }
        >
          <AsyncContent state={alerts} empty={(a) => a.length === 0} emptyLabel="No active conditions, correlations, or drift.">
            {(rows) => (
              <DataConsole
                rows={rows}
                rowKey={(r) => `${r.kind}:${r.id}`}
                onRowClick={setSelectedAlert}
                selectedKey={selectedAlert ? `${selectedAlert.kind}:${selectedAlert.id}` : null}
                columns={[
                  {
                    key: "sev",
                    header: "Sev",
                    width: "80px",
                    render: (r) => (r.severity ? <SeverityBadge severity={r.severity} /> : <span className="text-[10px] uppercase text-gray-500">correlation</span>),
                  },
                  { key: "kind", header: "Kind", width: "100px", render: (r) => r.kind },
                  { key: "title", header: "Title", render: (r) => <span className="text-gray-200">{r.title}</span> },
                  { key: "detail", header: "Detail", render: (r) => <span className="text-gray-500">{r.detail || "—"}</span> },
                  { key: "time", header: "Last observed", width: "150px", render: (r) => fmtTime(r.occurredAt) },
                ]}
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Active conditions by severity">
          <AsyncContent state={overview} empty={(o) => Object.keys(o.active_conditions_by_severity).length === 0} emptyLabel="No active security conditions.">
            {(o) => (
              <MiniBars
                data={Object.entries(o.active_conditions_by_severity)
                  .map(([label, value]) => ({ label, value }))
                  .sort((a, b) => b.value - a.value)}
                colorFor={(l) => SEVERITY_COLOR[l.toLowerCase()] ?? "#ef4444"}
              />
            )}
          </AsyncContent>
        </Panel>

        <Panel
          title="Asset inventory"
          right={<Link href="/assets" className="text-[11px] text-red-400 hover:text-red-300">manage →</Link>}
        >
          <AsyncContent state={overview} empty={(o) => o.total_assets === 0} emptyLabel="No assets in inventory yet.">
            {(o) => (
              <MiniBars
                data={Object.entries(o.asset_inventory_by_type)
                  .map(([label, value]) => ({ label, value }))
                  .sort((a, b) => b.value - a.value)
                  .slice(0, 10)}
                colorFor={() => "#60a5fa"}
              />
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel title="High-risk assets (multiple active conditions)">
          <AsyncContent state={overview} empty={(o) => o.high_risk_assets.length === 0} emptyLabel="No assets carry multiple active conditions.">
            {(o) => (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-[11px] uppercase tracking-wider text-gray-500">
                      <th className="py-2 pr-4">Asset</th>
                      <th className="py-2 pr-4">Type</th>
                      <th className="py-2 pr-4">Active conditions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {o.high_risk_assets.map((a) => (
                      <tr key={a.asset_id} className="border-b border-gray-800/60">
                        <td className="py-2 pr-4 text-gray-200">{a.asset_name}</td>
                        <td className="py-2 pr-4 text-gray-400">{a.asset_type}</td>
                        <td className="py-2 pr-4 tabular-nums text-red-300">{a.active_condition_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="Network zones" right={<Link href="/command-center/zones" className="text-[11px] text-red-400 hover:text-red-300">manage →</Link>}>
          <AsyncContent state={overview}>
            {(o) => {
              const entries = Object.entries(o.zone_counts).filter(([, v]) => v > 0);
              return entries.length === 0 ? (
                <div className="py-4 text-center text-xs text-gray-500">
                  No assets classified into zones yet. Zones are explicit admin assignments — never inferred from an IP.
                </div>
              ) : (
                <MiniBars
                  data={entries.map(([label, value]) => ({ label: ZONE_LABELS[label] ?? label, value }))}
                  colorFor={() => "#a78bfa"}
                />
              );
            }}
          </AsyncContent>
        </Panel>
        <Panel title="Jump to">
          <div className="grid grid-cols-2 gap-2 text-sm">
            {[
              ["Network operations", "/command-center/exposure"],
              ["Behavior analytics", "/command-center/behavior"],
              ["Telemetry / integrations", "/command-center/integrations"],
              ["Relationship map", "/command-center/map"],
              ["DMZ & zones", "/command-center/zones"],
              ["Full activity feed", "/security-operations"],
            ].map(([label, href]) => (
              <Link
                key={href}
                href={href}
                className="rounded-lg border border-gray-800 bg-gray-900/60 px-3 py-2 text-gray-300 hover:border-red-900 hover:text-red-300"
              >
                {label} →
              </Link>
            ))}
          </div>
        </Panel>
      </div>

      <InvestigationDrawer
        open={selectedEvent !== null}
        onClose={() => setSelectedEvent(null)}
        title={selectedEvent?.title ?? ""}
        subtitle="Operational event"
        fields={eventDrawerFields}
      />
      <InvestigationDrawer
        open={selectedAlert !== null}
        onClose={() => setSelectedAlert(null)}
        title={selectedAlert?.title ?? ""}
        subtitle={selectedAlert ? `Security alert · ${selectedAlert.kind}` : ""}
        fields={alertDrawerFields}
        links={
          selectedAlert?.kind === "condition"
            ? [{ label: "View asset", href: "/assets" }]
            : undefined
        }
      />
    </div>
  );
}
