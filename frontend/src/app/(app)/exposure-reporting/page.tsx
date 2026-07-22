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
  fmtTime,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import {
  generateReport,
  listReports,
  deliverReport,
  exportReport,
  getExposureReportingDashboard,
  getExposureReportingTrends,
  listBusinessImpactMappings,
  createBusinessImpactMapping,
  type ExposureReportDTO,
  type BusinessImpactMappingDTO,
} from "@/lib/exposureReporting";
import { getMe } from "@/lib/auth";

const REPORT_TYPES = ["EXECUTIVE_SUMMARY", "TECHNICAL_DETAIL", "TREND_ANALYSIS", "COMPLIANCE"];
const CRITICALITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const IMPACT_DOMAINS = ["FINANCIAL", "OPERATIONAL", "REPUTATIONAL", "REGULATORY", "SAFETY"];

export default function ExposureReportingPage() {
  const dashboard = useAsync(() => getExposureReportingDashboard(), []);
  const trends = useAsync(() => getExposureReportingTrends(), []);
  const reports = useAsync(() => listReports(), []);
  const mappings = useAsync(() => listBusinessImpactMappings(), []);
  const [tab, setTab] = useState<"dashboard" | "reports" | "mappings">("dashboard");
  const [selected, setSelected] = useState<ExposureReportDTO | null>(null);
  const [busy, setBusy] = useState(false);
  const [showGenerate, setShowGenerate] = useState(false);
  const [showMap, setShowMap] = useState(false);

  async function handleGenerate(reportType: string) {
    setBusy(true);
    try {
      const me = await getMe().catch(() => null);
      await generateReport({ report_type: reportType, generated_by: me?.email || "console" });
      reports.reload();
      setShowGenerate(false);
    } finally {
      setBusy(false);
    }
  }

  async function handleDeliver(report: ExposureReportDTO) {
    setBusy(true);
    try {
      await deliverReport(report.report_id);
      reports.reload();
    } finally {
      setBusy(false);
    }
  }

  async function handleExport(report: ExposureReportDTO, format: "json" | "markdown") {
    const text = await exportReport(report.report_id, format);
    const blob = new Blob([text], { type: format === "json" ? "application/json" : "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${report.report_id}.${format === "json" ? "json" : "md"}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <>
      <PageHeader
        title="Exposure Reporting"
        subtitle="Executive dashboards, exposure trend analysis, and business impact mapping"
        actions={
          <button
            onClick={() => setShowGenerate(true)}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50"
          >
            Generate Report
          </button>
        }
      />

      <div className="mb-4 flex gap-1 rounded-lg border border-gray-800 bg-gray-900 p-1">
        {(["dashboard", "reports", "mappings"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`rounded-md px-4 py-1.5 text-xs font-medium capitalize ${
              tab === t ? "bg-red-950/60 text-red-300" : "text-gray-400 hover:text-gray-200"
            }`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === "dashboard" && (
        <AsyncContent state={dashboard}>
          {(d) => (
            <>
              <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-4">
                <KpiTile label="Exposure Score" value={d.tenant_exposure_score.toFixed(1)} tone={d.tenant_exposure_score >= 7 ? "danger" : d.tenant_exposure_score >= 4 ? "warning" : "ok"} />
                <KpiTile label="Total Assets" value={d.asset_count} />
                <KpiTile label="Mapped Assets" value={d.mapped_asset_count} tone="ok" />
                <KpiTile label="Unmapped Assets" value={d.unmapped_asset_count} tone={d.unmapped_asset_count > 0 ? "warning" : "ok"} />
              </div>
              {d.data_freshness_warning && (
                <div className="mb-4 rounded-lg border border-amber-900/60 bg-amber-950/40 px-4 py-3 text-sm text-amber-300">
                  Data freshness warning: underlying exposure data may be stale.
                </div>
              )}
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                <Panel title="Top Exposed Assets">
                  {d.top_assets.length === 0 ? (
                    <p className="p-4 text-sm text-gray-500">No exposed assets found.</p>
                  ) : (
                    <div className="divide-y divide-gray-800">
                      {d.top_assets.map((a) => (
                        <div key={a.asset_ref_id} className="flex items-center justify-between px-4 py-2">
                          <span className="font-mono text-xs text-gray-400">{a.asset_ref_id.slice(0, 16)}…</span>
                          <span className="text-sm font-bold text-gray-200">{a.score.toFixed(1)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
                <Panel title="Key Performance Indicators">
                  {Object.keys(d.kpi).length === 0 ? (
                    <p className="p-4 text-sm text-gray-500">No KPI data available.</p>
                  ) : (
                    <div className="divide-y divide-gray-800">
                      {Object.entries(d.kpi).map(([k, v]) => (
                        <div key={k} className="flex items-center justify-between px-4 py-2">
                          <span className="text-xs text-gray-400">{k.replace(/_/g, " ")}</span>
                          <span className="text-sm font-semibold text-gray-200">{v}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>
              </div>
              {d.dominant_amplifier && (
                <p className="mt-4 text-xs text-gray-500">
                  Dominant risk amplifier: <span className="text-gray-300">{d.dominant_amplifier}</span>
                </p>
              )}
            </>
          )}
        </AsyncContent>
      )}

      {tab === "reports" && (
        <ReportsTab
          state={reports}
          onSelect={setSelected}
          onDeliver={handleDeliver}
          onExport={handleExport}
          busy={busy}
        />
      )}

      {tab === "mappings" && (
        <>
          <div className="mb-3 flex justify-end">
            <button
              onClick={() => setShowMap(true)}
              className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300 hover:border-red-800 hover:text-red-300"
            >
              Add Mapping
            </button>
          </div>
          <MappingsTab state={mappings} />
        </>
      )}

      {trends.data && trends.data.points.length > 0 && tab === "dashboard" && (
        <Panel title="Exposure Score Trend" className="mt-4">
          <div className="flex items-end gap-1 overflow-x-auto py-2">
            {trends.data.points.slice(-30).map((p, i) => (
              <div
                key={i}
                title={`${fmtTime(p.computed_at)}: ${p.tenant_exposure_score.toFixed(1)}`}
                className="w-3 shrink-0 rounded-t bg-red-700/70"
                style={{ height: `${Math.max(4, (p.tenant_exposure_score / 10) * 80)}px` }}
              />
            ))}
          </div>
        </Panel>
      )}

      {selected && (
        <InvestigationDrawer
          open
          title={selected.report_type.replace(/_/g, " ")}
          subtitle={selected.report_id}
          onClose={() => setSelected(null)}
          fields={reportFields(selected)}
        />
      )}

      {showGenerate && (
        <GenerateReportModal onClose={() => setShowGenerate(false)} onGenerate={handleGenerate} busy={busy} />
      )}

      {showMap && (
        <CreateMappingModal
          onClose={() => setShowMap(false)}
          onCreated={() => {
            mappings.reload();
            setShowMap(false);
          }}
        />
      )}
    </>
  );
}

function reportFields(r: ExposureReportDTO): DrawerField[] {
  return [
    { label: "Status", value: <StatusPill status={r.status} /> },
    { label: "Template", value: r.template_id },
    { label: "Generated By", value: r.generated_by },
    { label: "Generated At", value: fmtTime(r.generated_at) },
    { label: "Delivered At", value: r.delivered_at ? fmtTime(r.delivered_at) : "Not delivered" },
    { label: "Time Range", value: r.time_range_start ? `${fmtTime(r.time_range_start)} — ${fmtTime(r.time_range_end)}` : "All time" },
    { label: "Narrative", value: <span className="whitespace-pre-wrap text-xs">{r.narrative}</span> },
  ];
}

function ReportsTab({
  state,
  onSelect,
  onDeliver,
  onExport,
  busy,
}: {
  state: ReturnType<typeof useAsync<ExposureReportDTO[]>>;
  onSelect: (r: ExposureReportDTO) => void;
  onDeliver: (r: ExposureReportDTO) => void;
  onExport: (r: ExposureReportDTO, format: "json" | "markdown") => void;
  busy: boolean;
}) {
  const cols: ConsoleColumn<ExposureReportDTO>[] = [
    { key: "type", header: "Type", width: "20%", render: (r) => <span className="text-gray-200">{r.report_type.replace(/_/g, " ")}</span> },
    { key: "status", header: "Status", width: "12%", render: (r) => <StatusPill status={r.status} /> },
    { key: "generated_by", header: "Generated By", width: "16%", render: (r) => r.generated_by },
    { key: "generated_at", header: "Generated At", width: "16%", render: (r) => fmtTime(r.generated_at) },
    { key: "delivered", header: "Delivered", width: "12%", render: (r) => (r.delivered_at ? "Yes" : "No") },
    {
      key: "actions",
      header: "Actions",
      width: "24%",
      render: (r) => (
        <div className="flex gap-1.5" onClick={(e) => e.stopPropagation()}>
          <button
            disabled={busy || !!r.delivered_at}
            onClick={() => onDeliver(r)}
            className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300 hover:border-red-800 hover:text-red-300 disabled:opacity-40"
          >
            Deliver
          </button>
          <button
            onClick={() => onExport(r, "json")}
            className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            JSON
          </button>
          <button
            onClick={() => onExport(r, "markdown")}
            className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-300 hover:border-red-800 hover:text-red-300"
          >
            Markdown
          </button>
        </div>
      ),
    },
  ];
  return (
    <AsyncContent state={state} empty={(d) => d.length === 0} emptyLabel="No reports generated yet.">
      {(list) => (
        <DataConsole columns={cols} rows={list} rowKey={(r) => r.report_id} onRowClick={onSelect} emptyLabel="No reports generated yet." />
      )}
    </AsyncContent>
  );
}

function MappingsTab({ state }: { state: ReturnType<typeof useAsync<BusinessImpactMappingDTO[]>> }) {
  const cols: ConsoleColumn<BusinessImpactMappingDTO>[] = [
    { key: "asset", header: "Asset", width: "24%", render: (r) => <span className="font-mono text-xs text-gray-300">{r.asset_ref_id.slice(0, 16)}…</span> },
    { key: "criticality", header: "Criticality", width: "14%", render: (r) => <StatusPill status={r.criticality} /> },
    { key: "domain", header: "Impact Domain", width: "16%", render: (r) => r.impact_domain },
    { key: "unit", header: "Business Unit", width: "16%", render: (r) => r.business_unit_ref || "—" },
    { key: "financial", header: "Financial Impact", width: "14%", render: (r) => (r.financial_impact_estimate != null ? `$${r.financial_impact_estimate.toLocaleString()}` : "—") },
    { key: "scope", header: "Regulatory Scope", width: "16%", render: (r) => r.regulatory_scope.join(", ") || "—" },
  ];
  return (
    <AsyncContent state={state} empty={(d) => d.length === 0} emptyLabel="No business impact mappings defined.">
      {(list) => (
        <DataConsole columns={cols} rows={list} rowKey={(r) => r.asset_ref_id} emptyLabel="No business impact mappings defined." />
      )}
    </AsyncContent>
  );
}

function GenerateReportModal({
  onClose,
  onGenerate,
  busy,
}: {
  onClose: () => void;
  onGenerate: (reportType: string) => void;
  busy: boolean;
}) {
  const [reportType, setReportType] = useState(REPORT_TYPES[0]);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-sm rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h3 className="mb-3 text-sm font-semibold text-gray-100">Generate Exposure Report</h3>
        <label className="mb-1 block text-xs text-gray-500">Report Type</label>
        <select
          value={reportType}
          onChange={(e) => setReportType(e.target.value)}
          className="mb-4 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        >
          {REPORT_TYPES.map((t) => (
            <option key={t} value={t}>{t.replace(/_/g, " ")}</option>
          ))}
        </select>
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">
            Cancel
          </button>
          <button
            disabled={busy}
            onClick={() => onGenerate(reportType)}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
          >
            {busy ? "Generating…" : "Generate"}
          </button>
        </div>
      </div>
    </div>
  );
}

function CreateMappingModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: () => void;
}) {
  const [assetRefId, setAssetRefId] = useState("");
  const [criticality, setCriticality] = useState(CRITICALITY_LEVELS[0]);
  const [impactDomain, setImpactDomain] = useState(IMPACT_DOMAINS[0]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    if (!assetRefId.trim()) {
      setError("Asset reference ID is required.");
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const me = await getMe().catch(() => null);
      await createBusinessImpactMapping({
        asset_ref_id: assetRefId.trim(),
        criticality,
        impact_domain: impactDomain,
        authored_by: me?.email || "console",
      });
      onCreated();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create mapping");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
      <div className="w-full max-w-sm rounded-xl border border-gray-800 bg-gray-900 p-5">
        <h3 className="mb-3 text-sm font-semibold text-gray-100">Add Business Impact Mapping</h3>
        <label className="mb-1 block text-xs text-gray-500">Asset Reference ID</label>
        <input
          value={assetRefId}
          onChange={(e) => setAssetRefId(e.target.value)}
          className="mb-3 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
          placeholder="asset-ref-id"
        />
        <label className="mb-1 block text-xs text-gray-500">Criticality</label>
        <select
          value={criticality}
          onChange={(e) => setCriticality(e.target.value)}
          className="mb-3 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        >
          {CRITICALITY_LEVELS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <label className="mb-1 block text-xs text-gray-500">Impact Domain</label>
        <select
          value={impactDomain}
          onChange={(e) => setImpactDomain(e.target.value)}
          className="mb-4 w-full rounded-md border border-gray-700 bg-gray-950 px-2 py-1.5 text-sm text-gray-200"
        >
          {IMPACT_DOMAINS.map((d) => <option key={d} value={d}>{d}</option>)}
        </select>
        {error && <p className="mb-3 text-xs text-red-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button onClick={onClose} className="rounded-md border border-gray-700 px-3 py-1.5 text-xs text-gray-300">
            Cancel
          </button>
          <button
            disabled={busy}
            onClick={submit}
            className="rounded-md border border-red-800 bg-red-950/50 px-3 py-1.5 text-xs text-red-300 hover:bg-red-900/50 disabled:opacity-50"
          >
            {busy ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
